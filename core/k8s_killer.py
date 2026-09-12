"""
KubeWarden — K8sKiller

Finds the pod behind a cgroup_id (via PodResolver) and kills it,
leaving a Kubernetes Event with the reason — so that
`kubectl describe pod` / `kubectl get events` show what it was killed
for.

NOTE: dry_run=True by default — it only logs what it WOULD do.
Real deletion has to be enabled explicitly and deliberately.
"""

import os
import queue
import logging
import threading
from datetime import datetime, timezone

from kubernetes import client, config as kube_config

from core.pod_resolver import PodResolver

log = logging.getLogger("kubewarden.killer")


class K8sKiller:
    def __init__(self, in_cluster=True, dry_run=True, node_name=None,
                 exclude_namespaces=None, warn_only_namespaces=None,
                 repeat_tracker=None, metrics=None, workers=2):
        if in_cluster:
            kube_config.load_incluster_config()
        else:
            kube_config.load_kube_config()  # for local debugging from the node

        self.core_v1 = client.CoreV1Api()
        self.dry_run = dry_run
        self.resolver = PodResolver(core_v1=self.core_v1, node_name=node_name)
        # kube-system and KubeWarden itself are never killed, whatever
        # the score
        self.exclude_namespaces = set(exclude_namespaces or [])
        # Observed and alerted on, but never killed automatically
        self.warn_only_namespaces = set(warn_only_namespaces or [])
        # Repeated-detection tracker (may be None if disabled)
        self.repeat = repeat_tracker
        self.metrics = metrics

        # Slow operations (Event + API delete, ~70 ms per round trip)
        # go to separate threads. Otherwise they block the thread that
        # reads the perf buffer: with ten simultaneous detections that
        # is ~700 ms of blindness, during which at 700 events/s roughly
        # 500 events are lost — and an attack on the eleventh pod goes
        # unnoticed.
        self._api_queue = queue.Queue(maxsize=1000)
        # Deduplication: the same pod must not be queued twice while
        # the previous request is still being processed
        self._in_flight = set()
        self._lock = threading.Lock()

        for i in range(workers):
            t = threading.Thread(target=self._api_worker, daemon=True,
                                 name=f"kubewarden-api-{i}")
            t.start()

    def _api_worker(self):
        """Background handler for slow K8s calls."""
        while True:
            namespace, pod_name, reason = self._api_queue.get()
            try:
                try:
                    self._emit_event(namespace, pod_name, reason)
                except Exception as e:
                    # The Event is not critical — the pod still has to go
                    log.error(f"Event for {namespace}/{pod_name} not created: {e}")
                try:
                    self.kill_pod(namespace, pod_name)
                    log.info(f"API-delete done: {namespace}/{pod_name}")
                    if self.metrics is not None:
                        self.metrics.inc("api_deletes")
                except client.ApiException as e:
                    if e.status == 404:
                        # Not an error: cgroup.kill killed the processes,
                        # kubelet noticed and removed the pod before our
                        # queue got to it. Goal achieved.
                        log.info(f"{namespace}/{pod_name} already gone "
                                 f"(kubelet beat the API-delete)")
                    else:
                        log.error(f"API-delete {namespace}/{pod_name} "
                                  f"failed: {e}")
                        if self.metrics is not None:
                            self.metrics.inc("api_errors")
                except Exception as e:
                    log.error(f"API-delete {namespace}/{pod_name} failed: {e}")
            finally:
                with self._lock:
                    self._in_flight.discard((namespace, pod_name))
                self._api_queue.task_done()

    def resolve_pod(self, cgroup_id: int):
        """cgroup_id -> (namespace, pod_name) or None."""
        return self.resolver.resolve(cgroup_id)

    def freeze_and_kill_cgroup(self, cgroup_id: int) -> bool:
        """
        Instantly kill ALL processes in the cgroup via cgroup.kill
        (cgroup v2, kernel 5.14+). Returns True on success.

        Why this exists instead of a plain delete_namespaced_pod:
        the API delete is asynchronous. The API server writes to etcd
        and answers us, but the actual SIGKILL only arrives once kubelet
        receives the watch event and calls CRI StopContainer — that is
        5-30 seconds. With grace_period=0 the object disappears from
        etcd without waiting for kubelet at all, and the container keeps
        running "orphaned". During testing this made it possible to walk
        around a pod quite comfortably after a KILL had fired.

        cgroup.kill hits the whole cgroup hierarchy synchronously, in
        microseconds, and leaves the attacker no window to finish the
        job.
        """
        path = self.resolver.find_cgroup_path(cgroup_id)
        if not path:
            return False

        kill_file = os.path.join(path, "cgroup.kill")
        if not os.path.exists(kill_file):
            log.warning(f"{kill_file} unavailable (needs cgroup v2, "
                        f"kernel 5.14+) — only the asynchronous "
                        f"API-delete remains")
            return False

        try:
            with open(kill_file, "w") as f:
                f.write("1")
            log.info(f"cgroup.kill: all processes in cgroup={cgroup_id} killed")
            if self.metrics is not None:
                self.metrics.inc("cgroup_kills")
            return True
        except OSError as e:
            log.error(f"failed to write to {kill_file}: {e}")
            return False

    def handle_kill(self, cgroup_id: int, reason: str) -> bool:
        """
        The full path: cgroup_id -> pod -> checks -> kill.
        Returns True if the pod was actually dealt with.
        """
        pod = self.resolve_pod(cgroup_id)
        if pod is None:
            log.warning(f"cgroup={cgroup_id}: could not match to a pod "
                        f"(process may not be in a container) — kill skipped")
            if self.metrics is not None:
                self.metrics.inc("resolve_failures")
            return False

        namespace, pod_name = pod

        # Protection: system namespaces are never touched, even if the
        # score is off the charts. A false positive on kube-system can
        # take the cluster down.
        if namespace in self.exclude_namespaces:
            log.warning(f"{namespace}/{pod_name}: namespace is excluded — "
                        f"kill skipped (reason was: {reason})")
            return False

        # warn_only: the pod stays alive, but we create an Event — the
        # human sees the alert in `kubectl get events` and decides.
        # Automatic killing here is more dangerous than a missed attack:
        # taking down coredns/cilium on a false positive means taking
        # down the cluster.
        #
        # EXCEPTION — repetition. A single detection in production is
        # probably noise, but a third one within ten minutes is not.
        # Then we either escalate the alert or (if repeat.action ==
        # "kill") kill even here.
        if namespace in self.warn_only_namespaces:
            repeat_note = ""
            escalated = False
            if self.repeat is not None:
                owner = self.resolver.owner_of(cgroup_id) or f"{namespace}/{pod_name}"
                count, escalated, stamps = self.repeat.record(owner)
                if escalated and self.metrics is not None:
                    self.metrics.on_escalation(namespace)
                if count > 1:
                    repeat_note = self.repeat.describe(owner, stamps)

            if escalated and self.repeat.action == "kill":
                log.critical(f"{namespace}/{pod_name}: WARN-ONLY namespace, "
                             f"but REPEAT ESCALATION fired — killing. "
                             f"{repeat_note}. Reason: {reason}")
                # fall through to the normal kill path below
            else:
                level = log.critical if escalated else log.warning
                suffix = f" [{repeat_note}]" if repeat_note else ""
                level(f"{namespace}/{pod_name}: WARN-ONLY namespace — "
                      f"pod NOT killed, creating an Event for human triage."
                      f"{suffix} Reason: {reason}")
                if not self.dry_run:
                    tag = "WARN-ONLY, pod not killed"
                    if repeat_note:
                        tag += f"; {repeat_note}"
                    try:
                        self._emit_event(namespace, pod_name, f"[{tag}] {reason}")
                    except Exception as e:
                        log.error(f"Event for {namespace}/{pod_name} not created: {e}")
                return False

        if self.dry_run:
            log.critical(f"[DRY-RUN] would kill {namespace}/{pod_name} — {reason}")
            return False

        # 1) SYNCHRONOUS and instant: cgroup.kill stops every process in
        #    the pod within microseconds. This is the only
        #    time-critical action, and the only one we do on the hot
        #    path that reads the perf buffer.
        killed_locally = self.freeze_and_kill_cgroup(cgroup_id)

        # 2) ASYNCHRONOUS: Event and API-delete (~70 ms round trip each).
        #    Doing them here would stall the perf buffer reader for
        #    140 ms, and with a dozen simultaneous detections for over a
        #    second — losing hundreds of events from other pods in the
        #    meantime.
        key = (namespace, pod_name)
        with self._lock:
            already = key in self._in_flight
            if not already:
                self._in_flight.add(key)

        if not already:
            try:
                self._api_queue.put_nowait((namespace, pod_name, reason))
            except queue.Full:
                log.error(f"API task queue full, {namespace}/{pod_name} "
                          f"will not be deleted through the API "
                          f"(processes {'already killed' if killed_locally else 'NOT killed'})")
                with self._lock:
                    self._in_flight.discard(key)

        how = "cgroup.kill (instant)" if killed_locally else "WITHOUT local kill"
        log.critical(f"KILLED {namespace}/{pod_name} [{how}, API-delete queued] "
                     f"— {reason}")
        return True

    def kill_pod(self, namespace: str, pod_name: str):
        self.core_v1.delete_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body=client.V1DeleteOptions(grace_period_seconds=0),
        )

    def _emit_event(self, namespace, pod_name, reason):
        # The Event is written BEFORE deletion — afterwards there is
        # nothing left to attach it to
        now = datetime.now(timezone.utc)
        event = client.CoreV1Event(
            metadata=client.V1ObjectMeta(generate_name=f"kubewarden-{pod_name}-"),
            involved_object=client.V1ObjectReference(
                kind="Pod", name=pod_name, namespace=namespace,
            ),
            reason="KubeWardenThreatDetected",
            message=reason[:1024],  # k8s caps the message length
            type="Warning",
            source=client.V1EventSource(component="kubewarden"),
            # Legacy timestamps only (core/v1). Do NOT fill event_time:
            # it switches validation to the events.k8s.io/v1 format,
            # where action and reportingController are mandatory, and
            # the API returns 422 "action: Required value". These two
            # fields are enough for kubectl to show a time and sort by
            # it.
            first_timestamp=now,
            last_timestamp=now,
            count=1,
        )
        self.core_v1.create_namespaced_event(namespace, event)
        if self.metrics is not None:
            self.metrics.inc("events_emitted")
