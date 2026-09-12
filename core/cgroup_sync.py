"""
KubeWarden — CgroupSync

Proactively classifies the node's cgroups and stores the result in a
BPF map, so that the KERNEL can drop unwanted events before they ever
reach the perf buffer.

Why: during testing, 98% of events made it to user space only to be
discarded (host kubelet/containerd/etcd/calico). That produced
"Possibly lost N samples" and latency spikes up to 85 ms under burst.
Filtering in the kernel removes that work entirely.

CLASSIFICATION (fail-open by design):
    CLASS_HOST (2) — definitely a host cgroup (system.slice,
                     init.scope). The kernel does NOT submit its events.
    CLASS_POD  (1) — belongs to a pod. Submit.
    absent         — unknown. Submit.

Why fail-open: if a new pod is created before the next scan, its cgroup
is unknown. Fail-closed would blind us to that pod until the following
scan — an unacceptable window for a security agent. One extra event is
cheaper than a missed attack.

Synchronisation goes through cgroupfs rather than the K8s API:
cgroupfs is the source of truth on the node, works without an API
server, and never lags behind reality during fast pod create/delete.
"""

import os
import time
import ctypes as ct
import logging
import threading

log = logging.getLogger("kubewarden.cgroup_sync")

CGROUP_ROOT = "/sys/fs/cgroup"

CLASS_POD = 1
CLASS_HOST = 2
# Namespace listed in exclude_namespaces: events never leave the kernel.
# A deliberate blind spot — the operator decided noise costs more than
# visibility.
CLASS_EXCLUDED = 3
# Namespace listed in warn_only_namespaces: events reach user space,
# detection works, an Event is created — but there will be no automatic
# kill. This is the default for kube-system: a false kill of
# coredns/cilium takes down the cluster, and for someone running the
# agent for the first time that is the worst possible outcome.
CLASS_WARN_ONLY = 4

# Top-level directories whose contents are host-owned by definition.
# kubepods* is DELIBERATELY not here: everything under it is a pod.
HOST_TOP_LEVEL = ("system.slice", "init.scope", "user.slice", "dev-hugepages.mount")


class CgroupSync:
    """
    Background synchronisation of cgroup classification into a BPF map.

    Usage:
        sync = CgroupSync(bpf_map)
        sync.start()          # first scan + background thread
        ...
        sync.stop()
    """

    def __init__(self, bpf_map, interval_sec=5.0, resolver=None,
                 exclude_namespaces=None, warn_only_namespaces=None):
        """
        resolver: PodResolver — needed to learn a pod's namespace from
                  its cgroup. Without it namespace filtering does not
                  work and only the pod/host split remains.
        """
        self.map = bpf_map
        self.interval = interval_sec
        self.resolver = resolver
        self.exclude_namespaces = set(exclude_namespaces or [])
        self.warn_only_namespaces = set(warn_only_namespaces or [])
        self._stop = threading.Event()
        self._thread = None
        self.stats = {"pod": 0, "host": 0, "excluded": 0, "warn_only": 0,
                      "scans": 0, "last_scan_ms": 0.0}

    def _pod_class(self, cgroup_path):
        """
        Determine a pod cgroup's class, taking its namespace into
        account. The resolution happens here, in the BACKGROUND thread,
        so it does not make event handling in the hot path any more
        expensive.
        """
        if self.resolver is None:
            return CLASS_POD
        pod_uid = self.resolver.extract_pod_uid(cgroup_path)
        if not pod_uid:
            return CLASS_POD
        pod = self.resolver.lookup_pod(pod_uid)
        if not pod:
            return CLASS_POD  # namespace unknown yet — observe (fail-open)
        namespace, _ = pod
        if namespace in self.exclude_namespaces:
            return CLASS_EXCLUDED
        if namespace in self.warn_only_namespaces:
            return CLASS_WARN_ONLY
        return CLASS_POD

    # --- a single pass over cgroupfs -------------------------------------
    def scan_once(self):
        started = time.monotonic()
        counts = {CLASS_POD: 0, CLASS_HOST: 0,
                  CLASS_EXCLUDED: 0, CLASS_WARN_ONLY: 0}

        # 1) Pods: everything under kubepods* (including nested QoS
        #    slices). The class depends on the namespace, which we
        #    resolve in this background thread.
        for base in ("kubepods.slice", "kubepods"):
            root = os.path.join(CGROUP_ROOT, base)
            if not os.path.isdir(root):
                continue
            for dirpath, _, _ in os.walk(root):
                cls = self._pod_class(dirpath)
                if self._classify(dirpath, cls):
                    counts[cls] += 1

        # 2) Host: system.slice and the rest of the top level.
        #    This is where the bulk of the saving comes from — kubelet,
        #    containerd, etcd and kube-apiserver live here and are the
        #    noisiest processes on the node.
        for top in HOST_TOP_LEVEL:
            root = os.path.join(CGROUP_ROOT, top)
            if not os.path.isdir(root):
                continue
            for dirpath, _, _ in os.walk(root):
                if self._classify(dirpath, CLASS_HOST):
                    counts[CLASS_HOST] += 1

        self.stats.update({
            "pod": counts[CLASS_POD],
            "host": counts[CLASS_HOST],
            "excluded": counts[CLASS_EXCLUDED],
            "warn_only": counts[CLASS_WARN_ONLY],
            "scans": self.stats["scans"] + 1,
            "last_scan_ms": (time.monotonic() - started) * 1000,
        })
        return counts

    def _classify(self, dirpath, cls):
        """Write a cgroup's class into the map, keyed by its inode."""
        try:
            cgroup_id = os.stat(dirpath).st_ino
        except OSError:
            return False  # directory vanished between walk and stat — normal
        try:
            self.map[ct.c_uint64(cgroup_id)] = ct.c_uint8(cls)
            return True
        except Exception as e:
            log.debug(f"failed to write cgroup={cgroup_id} class={cls}: {e}")
            return False

    # --- background thread ------------------------------------------------
    def _loop(self, scan_immediately=False):
        if scan_immediately:
            # The first scan did not run synchronously (so as not to
            # block the start of polling) — do it here, first thing
            try:
                c = self.scan_once()
                log.info(f"cgroup-sync (first scan): pod={c[CLASS_POD]} "
                         f"host={c[CLASS_HOST]} "
                         f"warn_only={c[CLASS_WARN_ONLY]} "
                         f"excluded={c[CLASS_EXCLUDED]} "
                         f"in {self.stats['last_scan_ms']:.0f}ms")
            except Exception as e:
                log.error(f"first cgroupfs scan failed: {e}")

        while not self._stop.wait(self.interval):
            try:
                self.scan_once()
            except Exception as e:
                # Synchronisation must never bring the agent down: on
                # error the map simply keeps its previous contents, and
                # unknown cgroups continue to be submitted (fail-open)
                log.error(f"cgroupfs rescan failed: {e}")

    def start(self, blocking_first_scan=True):
        """
        blocking_first_scan=False — do not wait for the first scan,
        return control immediately.

        Why: the first scan runs synchronously and internally calls
        list_pod_for_all_namespaces (namespace resolution) — hundreds of
        milliseconds including an API server round trip. All that time
        the tracepoint probes are already attached and generating
        events, while poll_loop has not started yet — the buffer fills
        up and overflows. Measured via metrics: ~270 events lost at
        startup, then not a single one over hours of running.

        This is safe for pods: should_skip is fail-open, so an unknown
        cgroup is submitted to user space rather than dropped. Host
        classes are already marked by
        SyscallTracer._prefill_host_classes by this point.
        """
        if blocking_first_scan:
            c = self.scan_once()
            log.info(f"cgroup-sync: pod={c[CLASS_POD]} host={c[CLASS_HOST]} "
                     f"warn_only={c[CLASS_WARN_ONLY]} "
                     f"excluded={c[CLASS_EXCLUDED]} "
                     f"in {self.stats['last_scan_ms']:.0f}ms; "
                     f"rescan every {self.interval:.0f}s")
        else:
            log.info(f"cgroup-sync: first scan in background, "
                     f"rescan every {self.interval:.0f}s")

        self._thread = threading.Thread(
            target=self._loop, daemon=True,
            name="kubewarden-cgroup-sync",
            kwargs={"scan_immediately": not blocking_first_scan})
        self._thread.start()

    def stop(self):
        self._stop.set()

    def summary(self):
        return (f"scans={self.stats['scans']} pod={self.stats['pod']} "
                f"host={self.stats['host']} "
                f"warn_only={self.stats['warn_only']} "
                f"excluded={self.stats['excluded']} "
                f"last={self.stats['last_scan_ms']:.0f}ms")
