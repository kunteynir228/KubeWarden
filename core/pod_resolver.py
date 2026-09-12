"""
KubeWarden — PodResolver

Turns a cgroup_id from an eBPF event into a concrete
namespace/pod-name, so K8sKiller knows who to kill.

How it works (three steps):

1) The cgroup_id from bpf_get_current_cgroup_id() is NOT an arbitrary
   ID — it is the inode number of the cgroup directory in cgroupfs.
   So the path can be found by walking /sys/fs/cgroup and comparing
   st_ino.

2) In cgroup v2 on a kubeadm node a pod path looks like this:
   /sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/
     kubepods-burstable-pod775d7ebb_eae8_4b34_b3cf_ee1b0f8b6ea4.slice/
     cri-containerd-18bb1366...scope
   We extract the pod UID from it (underscores become dashes).

3) pod UID -> pod name/namespace via the API server. We filter the pod
   list by spec.nodeName (our node only) and match the UID in Python —
   more reliable than a field selector on metadata.uid, whose support
   depends on the version.

Both steps are cached: walking cgroupfs is expensive, and a cgroup_id
lives as long as its container.
"""

import os
import re
import socket
import logging

log = logging.getLogger("kubewarden.resolver")

CGROUP_ROOT = "/sys/fs/cgroup"

# kubepods-burstable-pod<UID>.slice | kubepods-pod<UID>.slice (Guaranteed QoS)
POD_UID_RE = re.compile(r"pod([0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})")
# cgroup v1 and some runtimes already use dashes in the UID
POD_UID_DASH_RE = re.compile(r"pod([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")


class PodResolver:
    def __init__(self, core_v1=None, node_name=None):
        """
        core_v1: kubernetes.client.CoreV1Api (or None — then only the
                 cgroup part works)
        node_name: node name; defaults to the NODE_NAME env var
                   (DaemonSet fieldRef) or the hostname
        """
        self.core_v1 = core_v1
        self.node_name = node_name or os.environ.get("NODE_NAME") or socket.gethostname()
        self._path_cache = {}   # cgroup_id -> cgroup path
        self._pod_cache = {}    # pod_uid  -> (namespace, name)
        self._owner_cache = {}  # pod_uid  -> "ns/Kind/name" of the owner
        # Negative cache: cgroup_ids that are not under kubepods (host
        # processes — kubelet, systemd, containerd). Without it every
        # one of their events would trigger a full os.walk over
        # cgroupfs, and those events are the majority.
        self._not_in_kubepods = set()

    def is_pod_cgroup(self, cgroup_id: int) -> bool:
        """
        Fast check: does this cgroup belong to a pod?
        Host processes (kubelet, systemd) live in system.slice — there
        is no point scoring or killing them: they are already on the
        host, there is nowhere for them to "escape the container" to.
        """
        if cgroup_id in self._path_cache:
            return True
        if cgroup_id in self._not_in_kubepods:
            return False
        found = self.find_cgroup_path(cgroup_id) is not None
        if not found:
            self._not_in_kubepods.add(cgroup_id)
        return found

    # --- Step 1: cgroup_id (inode) -> path in cgroupfs -------------------
    def find_cgroup_path(self, cgroup_id: int):
        if cgroup_id in self._path_cache:
            return self._path_cache[cgroup_id]

        # Search only under kubepods* — that is where pods live,
        # everything else is irrelevant
        for base in ("kubepods.slice", "kubepods"):
            root = os.path.join(CGROUP_ROOT, base)
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, _ in os.walk(root):
                try:
                    if os.stat(dirpath).st_ino == cgroup_id:
                        self._path_cache[cgroup_id] = dirpath
                        return dirpath
                except OSError:
                    continue  # directory vanished (container died) — fine
        return None

    # --- Step 2: path -> pod UID ----------------------------------------
    @staticmethod
    def extract_pod_uid(cgroup_path: str):
        m = POD_UID_RE.search(cgroup_path)
        if m:
            # cgroupfs replaces UID dashes with underscores — undo that
            return m.group(1).replace("_", "-")
        m = POD_UID_DASH_RE.search(cgroup_path)
        if m:
            return m.group(1)
        return None

    # --- Step 3: pod UID -> (namespace, name) ---------------------------
    def lookup_pod(self, pod_uid: str):
        if pod_uid in self._pod_cache:
            return self._pod_cache[pod_uid]
        if self.core_v1 is None:
            return None

        # Our node's pods only — on a large cluster this is far cheaper
        pods = self.core_v1.list_pod_for_all_namespaces(
            field_selector=f"spec.nodeName={self.node_name}"
        )
        result = None
        for pod in pods.items:
            uid = pod.metadata.uid
            self._pod_cache[uid] = (pod.metadata.namespace, pod.metadata.name)
            self._owner_cache[uid] = self._extract_owner(pod)
            if uid == pod_uid:
                result = (pod.metadata.namespace, pod.metadata.name)
        return result

    @staticmethod
    def _extract_owner(pod):
        """
        A stable identifier for the SOURCE of a pod.

        Needed for counting repeated detections: on a KILL the pod dies,
        the controller brings up a new one with a different name and a
        different cgroup_id. Counting by either of those would always
        give 1, and a repeated attack (say from a compromised image)
        would go unnoticed.

        We use ownerReferences rather than stripping a suffix with a
        regex: a Deployment pod is named app-7d9f8c4b5-x7k2p, a
        DaemonSet pod falco-5wsz7, a StatefulSet pod db-0 — there is no
        single rule. For a Deployment the owner is a ReplicaSet whose
        name changes on every rollout, so we additionally strip the
        ReplicaSet hash.
        """
        ns = pod.metadata.namespace
        refs = pod.metadata.owner_references or []
        if not refs:
            # Standalone pod (like our test ones) — count by its name
            return f"{ns}/{pod.metadata.name}"

        ref = refs[0]
        name = ref.name
        if ref.kind == "ReplicaSet":
            # app-7d9f8c4b5 -> app: otherwise a rollout would reset the counter
            parts = name.rsplit("-", 1)
            if len(parts) == 2 and len(parts[1]) >= 5:
                name = parts[0]
        return f"{ns}/{ref.kind}/{name}"

    def owner_of(self, cgroup_id: int):
        """
        cgroup_id -> stable owner identifier
        ("prod/Deployment/payment-api") or None.
        """
        path = self.find_cgroup_path(cgroup_id)
        if not path:
            return None
        pod_uid = self.extract_pod_uid(path)
        if not pod_uid:
            return None
        if pod_uid not in self._owner_cache:
            self.lookup_pod(pod_uid)   # fills both caches
        return self._owner_cache.get(pod_uid)

    # --- Everything together ---------------------------------------------
    def resolve(self, cgroup_id: int):
        """
        Returns (namespace, pod_name), or None if we could not match it
        (the process is not in a pod — a host systemd/kubelet, say).
        """
        path = self.find_cgroup_path(cgroup_id)
        if not path:
            log.debug(f"cgroup_id={cgroup_id}: no path found under kubepods")
            return None

        pod_uid = self.extract_pod_uid(path)
        if not pod_uid:
            log.debug(f"cgroup_id={cgroup_id}: no pod UID extracted from {path}")
            return None

        pod = self.lookup_pod(pod_uid)
        if not pod:
            log.debug(f"pod_uid={pod_uid}: pod not found on node {self.node_name}")
        return pod
