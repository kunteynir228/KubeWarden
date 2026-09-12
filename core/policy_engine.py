"""
KubeWarden — PolicyEngine

Reads thresholds from policies.yaml and turns an AttackStory into a
decision: ALLOW / WARN / KILL. The threshold is just a threat_score,
but the structure is ready for named rules (path regexes, specific
syscall chains and so on).
"""

import yaml
from enum import Enum


class Decision(Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    KILL = "KILL"


class PolicyEngine:
    def __init__(self, policy_path="policies/policies.yaml"):
        with open(policy_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

        self.warn_threshold = self.config["thresholds"]["warn"]
        self.kill_threshold = self.config["thresholds"]["kill"]
        # Namespaces we never kill in, whatever the score. Read from
        # YAML and passed to K8sKiller.
        self.exclude_namespaces = self.config.get("exclude_namespaces", [])
        # Namespaces under observation but without automatic kill:
        # detection and Events happen, the human decides.
        self.warn_only_namespaces = self.config.get("warn_only_namespaces", [])
        # Repeat escalation: a single detection in production is
        # probably noise, a third one within ten minutes is not.
        esc = self.config.get("repeat_escalation") or {}
        self.repeat_enabled = esc.get("enabled", True)
        self.repeat_window_sec = int(esc.get("window_minutes", 10)) * 60
        self.repeat_threshold = int(esc.get("threshold", 3))
        self.repeat_action = esc.get("action", "alert")

    def evaluate(self, story) -> Decision:
        if story.threat_score >= self.kill_threshold:
            return Decision.KILL
        if story.threat_score >= self.warn_threshold:
            return Decision.WARN
        return Decision.ALLOW

    def reason(self, story) -> str:
        # Build the reason shown to humans in logs and Events.
        # The comm of the last scoring event helps a lot when
        # triaging a false positive: you immediately see which
        # process did it.
        comm = story.last_comm()
        comm_part = f"proc={comm} " if comm else ""
        return (
            f"{comm_part}threat_score={story.threat_score} "
            f"chain=[{story.summary()}]"
        )
