"""
KubeWarden — main entrypoint

Wires the whole pipeline together:
  SyscallTracer -> AttackCorrelator -> PolicyEngine -> (Logger | K8sKiller)

Start in the safest mode and work up:
  --no-k8s                       detection only, no API calls
  (default)                      dry-run: resolves pods, logs "would kill"
  --enforce                      actually kill pods
  --enforce --kernel-enforce     also kill in-kernel on red lines
"""

import argparse
import logging
import time

from bpf.syscall_tracer import SyscallTracer
from core.correlator import AttackCorrelator
from core.policy_engine import PolicyEngine, Decision

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("kubewarden")


def main():
    ap = argparse.ArgumentParser(description="KubeWarden runtime security agent")
    ap.add_argument("--enforce", action="store_true",
                    help="actually kill pods (default is dry-run: log only)")
    ap.add_argument("--no-k8s", action="store_true",
                    help="no API server calls — detection and logging only")
    ap.add_argument("--in-cluster", action="store_true",
                    help="use the pod's ServiceAccount (for the DaemonSet); "
                         "defaults to ~/.kube/config")
    ap.add_argument("--kernel-enforce", action="store_true",
                    help="arm cgroups in the kernel on WARN: the next "
                         "chroot/mount/setns is killed via bpf_send_signal "
                         "in microseconds, without waiting for user space")
    ap.add_argument("--no-kernel-filter", action="store_true",
                    help="disable in-kernel filtering of host events "
                         "(for performance comparison)")
    ap.add_argument("--sync-interval", type=float, default=5.0,
                    help="how often to rescan cgroupfs, seconds (default 5)")
    ap.add_argument("--metrics-port", type=int, default=9102,
                    help="port for the Prometheus metrics endpoint (0 = off)")
    args = ap.parse_args()

    # Metrics are created first: they are collected from every
    # component, including the perf buffer hot path
    metrics = None
    if args.metrics_port:
        import os
        from core.metrics import Metrics, start_server
        metrics = Metrics(node_name=os.environ.get("NODE_NAME", "unknown"))
        start_server(metrics, args.metrics_port)

    correlator = AttackCorrelator()
    policy = PolicyEngine("policies/policies.yaml")

    # The resolver is always needed, even with --no-k8s: its cgroup part
    # works without an API server and answers the key question — is this
    # process in a pod or on the host. Host processes (kubelet, systemd,
    # containerd) are never scored: they have nowhere to "escape the
    # container" to, and their routine volume mount/umount would
    # otherwise reach the kill threshold.
    from core.pod_resolver import PodResolver
    resolver = PodResolver()

    killer = None
    if not args.no_k8s:
        # Imported inside the branch: the kubernetes package is only
        # needed in this mode
        from core.k8s_killer import K8sKiller

        repeat_tracker = None
        if policy.repeat_enabled:
            from core.repeat_tracker import RepeatTracker
            repeat_tracker = RepeatTracker(
                window_sec=policy.repeat_window_sec,
                threshold=policy.repeat_threshold,
                action=policy.repeat_action,
            )
            log.info(f"repeat escalation: {policy.repeat_threshold} "
                     f"detections within {policy.repeat_window_sec // 60} min "
                     f"-> {policy.repeat_action}")

        killer = K8sKiller(
            in_cluster=args.in_cluster,
            dry_run=not args.enforce,
            exclude_namespaces=policy.exclude_namespaces,
            warn_only_namespaces=policy.warn_only_namespaces,
            repeat_tracker=repeat_tracker,
            metrics=metrics,
        )
        # Let the killer and main share one resolver — shared cache
        resolver = killer.resolver
        mode = "ENFORCE (pods will be killed)" if args.enforce else "DRY-RUN"
        log.info(f"K8s integration enabled, mode: {mode}")
    else:
        log.info("K8s integration disabled (--no-k8s): detection only")

    # Without this, main.py would log CRITICAL for EVERY subsequent
    # event in the chain until the story falls out of
    # CORRELATION_WINDOW_SEC — once threat_score crosses
    # kill_threshold, each new event from the same cgroup_id yields
    # decision=KILL again. We track the last decision per cgroup_id and
    # only react to a state change (a transition into WARN/KILL).
    last_decision = {}

    def on_event(event):
        # Filter out host processes BEFORE scoring. Their absence was
        # exactly why kubelet's mount(tmpfs) plus
        # openat(/var/lib/kubelet/pods/...) added up to threat_score=100
        # and reached a KILL decision — the only thing that saved us was
        # the resolver failing to find a pod afterwards.
        # Separately important: our own kill triggers volume cleanup
        # (umount), which without this filter looked like an attack
        # again.
        if not resolver.is_pod_cgroup(event["cgroup_id"]):
            return

        # An event the kernel has ALREADY sent SIGKILL for — the
        # response happened in microseconds, here we only record it
        if event.get("killed_in_kernel"):
            log.critical(
                f"cgroup={event['cgroup_id']} KILLED IN KERNEL: "
                f"{event['syscall']}({event['filename']}) proc={event['comm']} "
                f"pid={event['pid']} (latency {event['latency_ms']:.2f}ms)"
            )

        story = correlator.process(event)
        decision = policy.evaluate(story)

        if decision == Decision.ALLOW:
            last_decision.pop(story.cgroup_id, None)
            return  # noise — not logged, to avoid filling the disk

        if last_decision.get(story.cgroup_id) == decision:
            return  # this alert level has already been logged for this chain

        last_decision[story.cgroup_id] = decision
        reason = policy.reason(story)

        if metrics is not None:
            # The namespace is cheap to get: the resolver caches it, and
            # on WARN this also warms the cache ahead of a possible KILL
            pod = resolver.resolve(story.cgroup_id) if resolver else None
            ns = pod[0] if pod else "unknown"
            metrics.on_detection(ns, decision.value)

        if decision == Decision.WARN:
            log.warning(f"cgroup={story.cgroup_id} {reason}")
            # The key part of the hybrid scheme: we arm the cgroup IN
            # ADVANCE, at the WARN stage. The attacker has only read
            # /etc/shadow so far, but their next chroot/mount will
            # already be killed in the kernel — with no window in which
            # they could previously walk around the pod at leisure.
            if args.kernel_enforce and tracer_ref["t"] is not None:
                if tracer_ref["t"].arm(story.cgroup_id):
                    log.info(f"cgroup={story.cgroup_id} ARMED: "
                             f"chroot/mount/setns will now be killed in-kernel")
        elif decision == Decision.KILL:
            log.critical(f"cgroup={story.cgroup_id} KILL — {reason}")
            if killer is not None:
                killed = killer.handle_kill(story.cgroup_id, reason)
                if killed:
                    # The pod is dead — forget the story, otherwise
                    # residual events would keep generating WARNs about
                    # an already deleted pod
                    correlator.forget(story.cgroup_id)
                    last_decision.pop(story.cgroup_id, None)
                    if tracer_ref["t"] is not None:
                        tracer_ref["t"].disarm(story.cgroup_id)

    # on_event references the tracer, and the tracer is constructed with
    # on_event — we break the circular dependency through a container
    tracer_ref = {"t": None}
    tracer = SyscallTracer(on_event=on_event,
                           kernel_enforce=args.kernel_enforce,
                           metrics=metrics)
    tracer_ref["t"] = tracer

    # Gauge values are refreshed in the background rather than at
    # /metrics render time: reading a BPF map and counting caches should
    # not depend on how often Prometheus scrapes the endpoint.
    #
    # Once a minute, no more often: these are slow-moving quantities
    # (how many cgroups in each class, cache sizes, armed cgroups).
    # More frequently makes no sense — Prometheus scrapes every 30
    # seconds anyway, and the event counters are updated on the hot
    # path and do not depend on this thread.
    if metrics is not None:
        def _update_gauges():
            armed = len(tracer.armed_list())
            sync = tracer.cgroup_sync
            classes = {}
            sync_ms = 0.0
            if sync is not None:
                st = sync.stats
                classes = {
                    "pod": st["pod"], "host": st["host"],
                    "warn_only": st["warn_only"], "excluded": st["excluded"],
                }
                sync_ms = st["last_scan_ms"]
            caches = {
                "path": len(resolver._path_cache),
                "pod": len(resolver._pod_cache),
                "owner": len(resolver._owner_cache),
                "not_in_kubepods": len(resolver._not_in_kubepods),
            }
            rs = 0
            if killer is not None and killer.repeat is not None:
                rs = len([1 for v in killer.repeat._history.values() if v])
            metrics.set_gauges(armed_count=armed, cgroup_classes=classes,
                               cache_entries=caches, repeat_sources=rs,
                               last_sync_ms=sync_ms)

        def _gauge_loop():
            while True:
                time.sleep(60)
                try:
                    _update_gauges()
                except Exception as e:
                    # Metrics must never bring the agent down
                    log.debug(f"gauge refresh failed: {e}")

        # First pass immediately, otherwise every gauge would read zero
        # for the first minute
        try:
            _update_gauges()
        except Exception as e:
            log.debug(f"initial gauge refresh failed: {e}")

        import threading
        threading.Thread(target=_gauge_loop, daemon=True,
                         name="kubewarden-gauges").start()

    # In-kernel filtering: after this, events from host processes
    # (kubelet, containerd, etcd, calico) never leave the kernel at all
    if not args.no_kernel_filter:
        tracer.start_cgroup_sync(
            interval_sec=args.sync_interval,
            resolver=resolver,
            exclude_namespaces=policy.exclude_namespaces,
            warn_only_namespaces=policy.warn_only_namespaces,
        )

    if args.kernel_enforce:
        log.info("KERNEL-ENFORCE enabled: cgroups are armed on WARN, "
                 "escape syscalls are killed in-kernel (bpf_send_signal)")

    log.info("KubeWarden started, watching syscalls...")
    tracer.poll_loop()


if __name__ == "__main__":
    main()
