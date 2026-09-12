"""
KubeWarden — AttackCorrelator

Individual syscalls mean very little on their own. "openat /etc/passwd"
can be a perfectly normal read. But "openat /etc/shadow" -> "execve
/bin/chroot" -> "chroot /" within two seconds in the same cgroup is a
chain — an Attack Story.

Here we group events by cgroup_id (= container) and compute a
threat_score.
"""

import time
from collections import defaultdict, deque

# Signal weights.
#
# NOTE on ServiceAccount tokens: the path
# /var/run/secrets/kubernetes.io/serviceaccount/token is DELIBERATELY
# absent. Every pod in the cluster reads its own token — that is normal
# API server authentication, not an attack. During testing this caused
# a false positive: metrics-server read its own token twice and hit the
# kill threshold. What IS suspicious is reading ANOTHER pod's token,
# through the kubelet directory or another process's /proc/<pid>/root —
# those paths are listed below.
#
# !!! MATCHING IS BY PATH COMPONENT BOUNDARY, NOT BY SUBSTRING !!!
# The naive `if prefix in filename` caused an outage on a live cluster:
# the rule "/host" matched "/etc/hosts" and "/opt/hostedtoolcache/...",
# so Trivy accumulated 120 points on a completely routine read of
# /etc/hosts and got killed on both nodes. /etc/hosts is read by every
# networked application — that rule would have wiped out half the
# cluster.
SUSPICIOUS_PATH_PREFIXES = {
    "/etc/shadow": 60,
    "/etc/kubernetes": 40,          # control plane PKI and manifests
    "/var/lib/kubelet/pods": 50,    # other pods' tokens and secrets
    # Access to the host filesystem through /proc/1/* is conclusive on
    # its own: there is no legitimate reason to read the host root via
    # PID 1.
    "/proc/1/root": 100,            # escaping into the host mount namespace
    "/proc/1/ns": 100,              # setns target (`nsenter --target 1`)
    # /host is a SPECIAL CASE, weight lowered to "suspicion" only.
    # It is not an attack indicator but a CONVENTION: every
    # runtime-security and observability agent mounts the host
    # filesystem there — Falco, Tetragon, node-exporter, Datadog.
    # On a live cluster the rule with weight 100 killed Falco for
    # reading /host/usr/src/ (kernel headers, exactly what KubeWarden
    # itself reads through /usr/src).
    #
    # The verdict here comes from SUFFIXES: /host/etc/shadow = 30 + 60
    # = 90, /host/etc/kubernetes/admin.conf = 30 + 100 = 130. Harmless
    # /host/usr/src/ stays at 30 — below the WARN threshold.
    "/host": 30,
}

# Sensitive files that are dangerous in ANY location: an attacker may
# read them through a host mount or /proc/<pid>/root rather than by
# their canonical path. Matched against the end of the path, on a
# component boundary.
SUSPICIOUS_PATH_SUFFIXES = {
    # Weight aligned with the prefix: reading /etc/shadow directly
    # scores 60 (WARN, needs a chain), while reading it through a host
    # mount — /host/etc/shadow — scores 30 + 60 = 90 (immediate KILL;
    # there is no reason to read the host's password hashes).
    "/etc/shadow": 60,
    "/etc/kubernetes/pki/ca.key": 100,   # the CA key lets you issue a
    "/etc/kubernetes/admin.conf": 100,   # system:masters certificate
    "/.ssh/id_rsa": 60,
    "/.ssh/authorized_keys": 60,
}

# Separate dictionary for basenames: a runtime socket can live at
# different paths (/run/..., /var/run/...), so we match the file name.
# Full paths do not work here — they would overlap each other
# (/run/docker.sock inside /var/run/docker.sock) and stack weights.
SUSPICIOUS_FILENAMES = {
    # Container runtime sockets. The weight is above kill_threshold
    # DELIBERATELY: this is not suspicion but full node access already
    # achieved. Through the socket you can ask the runtime to start a
    # privileged container with hostPath:/ — with no escape syscall at
    # all and without the pod itself being privileged.
    #
    # False positive risk: image scanners and some observability agents
    # legitimately talk to the runtime socket. They usually live in
    # kube-system/monitoring, which falls under warn_only. If such a pod
    # lives in another namespace, add that namespace to
    # warn_only_namespaces.
    "docker.sock": 100,
    "containerd.sock": 100,
    "crio.sock": 100,
}

# Syscall weights. IMPORTANT about mount: modern util-linux barely uses
# mount(2) — during testing `mount --bind` went through open_tree() +
# move_mount() (the new mount API, kernel 5.2+) and the escape went
# completely unnoticed. Hence weights for every variant.
SUSPICIOUS_SYSCALLS = {
    "chroot": 50,
    "mount": 70,        # mounting from inside a container is already an
    "move_mount": 70,   # escape; no point waiting for the chain to
    "fsmount": 70,      # continue — together with execve(/bin/mount)
                        # this is an immediate KILL
    "open_tree": 20,    # preparation only, harmless on its own
    # setns and pivot_root weigh above kill_threshold (90) ON PURPOSE:
    # this is an escape that already happened, not a suspicion. During
    # testing setns with weight 70 only produced a WARN, and
    # `nsenter --target 1` successfully dropped the operator into the
    # host namespace. In the kernel these two syscalls are additionally
    # handled as an unconditional red line (red_line_kill).
    "pivot_root": 100,
    "setns": 100,
    # Kernel module operations — the ceiling of severity: whoever loads
    # a module owns the kernel and can unload KubeWarden itself. There
    # is no legitimate reason to do this from inside a container.
    "init_module": 100,
    "finit_module": 100,
    "delete_module": 100,
    "ptrace": 40,       # process injection; with hostPID, into host
                        # processes
}

CORRELATION_WINDOW_SEC = 30  # events older than the window are evicted


def _is_library(path: str) -> bool:
    # Shared library loading and the linker cache are not attack steps.
    # execve(/proc/self/fd/N) belongs here too: that is a runc stage,
    # not a binary someone chose to run.
    return (
        ".so" in path
        or path.endswith("ld.so.cache")
        or path.startswith("/proc/self/fd/")
    )


def _path_matches(filename: str, prefix: str) -> bool:
    """
    Match on a PATH COMPONENT BOUNDARY, not on substring.

    "/host" matches "/host" and "/host/etc/shadow", but NOT
    "/etc/hosts", "/hostname" or "/opt/hostedtoolcache/...".

    The absence of this check is exactly what killed Trivy on a live
    cluster: it read /etc/hosts, the naive `"/host" in "/etc/hosts"`
    returned True, and the pod accumulated 120 points doing its normal
    job.
    """
    return filename == prefix or filename.startswith(prefix + "/")


class AttackStory:
    """A chain of events for one container plus the accumulated score."""

    def __init__(self, cgroup_id):
        self.cgroup_id = cgroup_id
        self.events = deque()  # items: (event, score_delta)
        self.threat_score = 0

    def add(self, event, score_delta):
        self.events.append((event, score_delta))
        self.threat_score += score_delta
        self._evict_old()

    def _evict_old(self):
        # IMPORTANT: when an event leaves the window we must subtract
        # its contribution to threat_score. Otherwise the score grows
        # monotonically and never falls — a legitimate pod that reads
        # /var/run/secrets/.../token once per reconcile loop would
        # eventually cross kill_threshold purely by accumulation,
        # without a single real violation.
        #
        # NOTE: event ts comes from the kernel (bpf_ktime_get_ns
        # converted to CLOCK_MONOTONIC seconds), so we use monotonic
        # time here too, not time.time(). Mixing them would put the
        # cutoff far in the future (wall clock >> uptime) and the window
        # would instantly discard every event, so no chain would ever
        # form.
        cutoff = time.monotonic() - CORRELATION_WINDOW_SEC
        while self.events and self.events[0][0]["ts"] < cutoff:
            _, old_score = self.events.popleft()
            self.threat_score -= old_score

    def last_comm(self):
        # comm of the last event that scored — that is the interesting
        # one when triaging, not the last library load
        for e, score in reversed(self.events):
            if score > 0:
                return e.get("comm")
        return self.events[-1][0].get("comm") if self.events else None

    def summary(self):
        # Human-readable description of the chain, for logs and for the
        # kill reason.
        #
        # Only SIGNIFICANT steps make it in: events that scored, plus
        # execve (which binaries were started — that is the plot of the
        # attack). Otherwise the chain drowns in dynamic linker work:
        # during testing, 45 of ~50 steps were openat() on ld.so.cache
        # and libm.so.6 probed across every glibc-hwcaps path — pure
        # noise for an analyst.
        steps = []
        for e, score in self.events:
            is_scored = score > 0
            is_exec = e["syscall"] == "execve" and not _is_library(e["filename"])
            if is_scored or is_exec:
                steps.append(f"{e['syscall']}({e['filename']})")
        return " -> ".join(steps)


class AttackCorrelator:
    def __init__(self):
        self.stories = defaultdict(lambda: None)

    def _score_event(self, event):
        filename = event["filename"]
        score = 0

        # Path prefixes — strictly on a component boundary
        matched_prefix = None
        for prefix, weight in SUSPICIOUS_PATH_PREFIXES.items():
            if _path_matches(filename, prefix):
                score += weight
                matched_prefix = prefix

        # Suffixes — a sensitive file is dangerous anywhere:
        # /etc/shadow, /host/etc/shadow, /proc/1/root/etc/shadow.
        # Skipped if the same path already scored as a prefix —
        # otherwise a direct read of /etc/shadow would count twice.
        for suffix, weight in SUSPICIOUS_PATH_SUFFIXES.items():
            if suffix == matched_prefix:
                continue
            if filename.endswith(suffix):
                score += weight

        # Basenames — a socket can live at different paths.
        # os.path.basename is avoided: filename comes from the kernel
        # and may be relative or truncated.
        base = filename.rsplit("/", 1)[-1]
        score += SUSPICIOUS_FILENAMES.get(base, 0)

        score += SUSPICIOUS_SYSCALLS.get(event["syscall"], 0)
        return score

    def process(self, event) -> AttackStory:
        """
        Takes a raw event from SyscallTracer and returns the updated
        AttackStory for the corresponding container.
        """
        cgroup_id = event["cgroup_id"]
        story = self.stories[cgroup_id]
        if story is None:
            story = AttackStory(cgroup_id)
            self.stories[cgroup_id] = story

        score_delta = self._score_event(event)
        story.add(event, score_delta)
        return story

    def forget(self, cgroup_id):
        """
        Drop the history for a cgroup — called after a kill.
        Without this, residual events from an already dead pod keep
        sitting in the correlation window and generate WARNs about a
        corpse.
        """
        self.stories.pop(cgroup_id, None)
