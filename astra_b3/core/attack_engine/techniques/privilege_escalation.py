"""
core/attack_engine/techniques/privilege_escalation.py
"""
from __future__ import annotations
import random
from typing import Any
from config.constants import KillChainPhase, Severity
from core.attack_engine.techniques.base import BaseTechnique, AttackStep


class TokenImpersonation(BaseTechnique):
    TECHNIQUE_ID   = "T1134.001"
    TECHNIQUE_NAME = "Access Token Manipulation: Token Impersonation/Theft"
    TACTIC         = "privilege_escalation"
    PHASE          = KillChainPhase.EXPLOITATION
    BASE_SEVERITY  = Severity.HIGH

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host    = context.get("initial_access_host", self._fake_hostname())
        from_   = context.get("initial_access_user", self._fake_username())
        to_     = random.choice(["SYSTEM", "NT AUTHORITY\\SYSTEM", "Administrator"])
        success = self._did_succeed()
        if success:
            context["current_privilege"] = "SYSTEM"
        return self._make_step(
            description=f"Token impersonation on {host}: escalated from {from_} → {to_}",
            source_host=host, target_host=host, success=success,
            severity=Severity.CRITICAL.value if success else Severity.MEDIUM.value,
            extra_data={"from_user": from_, "to_user": to_, "method": "SeImpersonatePrivilege abuse"},
        )


class SudoAbuse(BaseTechnique):
    TECHNIQUE_ID   = "T1548.003"
    TECHNIQUE_NAME = "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
    TACTIC         = "privilege_escalation"
    PHASE          = KillChainPhase.EXPLOITATION
    BASE_SEVERITY  = Severity.HIGH

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host    = context.get("initial_access_host", self._fake_hostname("LNX"))
        user    = context.get("initial_access_user", self._fake_username())
        cve     = random.choice(["CVE-2021-3156", "CVE-2019-14287", "sudo NOPASSWD misconfiguration"])
        success = self._did_succeed()
        if success:
            context["current_privilege"] = "root"
        return self._make_step(
            description=f"Linux privilege escalation via {cve} on {host} — {'root obtained' if success else 'failed'}",
            source_host=host, target_host=host, success=success,
            extra_data={"user": user, "method": cve, "target_user": "root"},
        )
