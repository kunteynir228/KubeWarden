"""
KubeWarden — RepeatTracker

Counts repeated KILL decisions per pod OWNER rather than per cgroup.

Why this exists
---------------
In production, few people are willing to kill pods on a single
detection — it is a running business service, and the cost of a false
kill is higher than the cost of a delayed response. So those
namespaces end up in warn_only: detection happens, automatic killing
does not.

But then an important signal is lost. A single WARN in production is
probably noise or a rare legitimate case. A repeat of the same chain
is not: legitimate applications either do something always or never.
An attacker tries, gets refused, tries differently.

This tracker adds a third tier between "stay quiet" and "kill":
escalation by repetition. The on-call engineer gets not one more log
line but "third detection within 8 minutes, here is when" — something
you can take to the service owner to justify a restart.

Why by owner and not by cgroup
-------------------------------
After a KILL the pod dies and the controller creates a new one — with
a different name and a different cgroup_id. A per-cgroup counter would
always read 1, and a repeated attack (for example from a compromised
image that keeps restarting) would stay invisible.

The owner is resolved through ownerReferences (see
PodResolver.owner_of); for Deployments the ReplicaSet hash is
additionally stripped, otherwise a rollout would reset the history.

Memory footprint
----------------
An entry appears ONLY on a KILL decision, not for every pod. In a
healthy cluster that is a handful of entries per day. The key is a
string like "ns/Kind/name", the value a deque of a few floats — on the
order of a hundred bytes per entry. Even with a thousand triggering
sources that is ~100 KB. Entries older than the window are dropped on
every access.
"""

import time
import logging
from collections import defaultdict, deque

log = logging.getLogger("kubewarden.repeat")


class RepeatTracker:
    def __init__(self, window_sec=600, threshold=3, action="alert"):
        """
        window_sec: observation window (10 minutes by default)
        threshold:  how many KILL decisions in the window count as
                    escalation
        action:     "alert" — log tag and Event note only
                    "kill"  — kill even in a warn_only namespace
        """
        self.window = window_sec
        self.threshold = threshold
        self.action = action
        self._history = defaultdict(deque)   # owner -> deque[timestamp]

    def record(self, owner: str):
        """
        Record a KILL decision for an owner.
        Returns (count, escalated, timestamps):
            count       — detections in the window including this one
            escalated   — whether the threshold was reached
            timestamps  — detection times, for human-readable output
        """
        now = time.monotonic()
        hist = self._history[owner]
        hist.append(now)

        # Drop whatever left the window. Same mechanism as the
        # correlation window — without it the history would grow
        # forever.
        cutoff = now - self.window
        while hist and hist[0] < cutoff:
            hist.popleft()

        count = len(hist)
        return count, count >= self.threshold, list(hist)

    def describe(self, owner: str, timestamps) -> str:
        """Human-readable summary for logs and Events."""
        if len(timestamps) < 2:
            return ""
        span_sec = timestamps[-1] - timestamps[0]
        return (f"REPEAT: detection #{len(timestamps)} for {owner} "
                f"within {span_sec / 60:.0f} min")

    def forget(self, owner: str):
        """Reset the history (for example after triaging an incident)."""
        self._history.pop(owner, None)

    def summary(self):
        """For metrics and debugging."""
        active = {k: len(v) for k, v in self._history.items() if v}
        return f"sources under observation: {len(active)}"
