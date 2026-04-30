"""
core/attack_engine/techniques/lateral_movement.py
──────────────────────────────────────────────────
MITRE ATT&CK Lateral Movement techniques.
  - T1021.001  Remote Desktop Protocol
  - T1021.002  SMB/Windows Admin Shares
  - T1550.002  Pass the Hash
  - T1550.003  Pass the Ticket
"""

from __future__ import annotations
import random
from typing import Any
from config.constants import KillChainPhase, Severity
from core.attack_engine.techniques.base import BaseTechnique, AttackStep


class RDPLateralMovement(BaseTechnique):
    TECHNIQUE_ID   = "T1021.001"
    TECHNIQUE_NAME = "Remote Services: Remote Desktop Protocol"
    TACTIC         = "lateral_movement"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.HIGH

    def execute(self, context: dict[str, Any]) -> AttackStep:
        src_host = context.get("initial_access_host", self._fake_hostname())
        tgt_host = self._fake_hostname("SRV")
        user     = context.get("initial_access_user", self._fake_username())
        success  = self._did_succeed()

        if success:
            context.setdefault("compromised_hosts", []).append(tgt_host)
            context["current_host"] = tgt_host

        return self._make_step(
            description=f"RDP lateral movement: {src_host} → {tgt_host} as '{user}' — {'connected' if success else 'blocked by NLA/firewall'}",
            source_host=src_host, target_host=tgt_host, success=success,
            extra_data={
                "username": user, "port": 3389,
                "auth_type": "NTLM" if self.difficulty != "expert" else "Kerberos",
                "network_level_auth": not success,
            },
        )


class SMBAdminShares(BaseTechnique):
    TECHNIQUE_ID   = "T1021.002"
    TECHNIQUE_NAME = "Remote Services: SMB/Windows Admin Shares"
    TACTIC         = "lateral_movement"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.HIGH

    def execute(self, context: dict[str, Any]) -> AttackStep:
        src_host = context.get("initial_access_host", self._fake_hostname())
        tgt_ip   = self._fake_ip(internal=True)
        share    = random.choice(["ADMIN$", "C$", "IPC$"])
        user     = context.get("initial_access_user", self._fake_username())
        success  = self._did_succeed()

        if success:
            context.setdefault("compromised_hosts", []).append(tgt_ip)

        return self._make_step(
            description=f"SMB share access: {src_host} → \\\\{tgt_ip}\\{share} as {user}",
            source_host=src_host, target_host=tgt_ip, success=success,
            extra_data={"share": share, "user": user, "port": 445, "proto": "SMBv2"},
        )


class PassTheHash(BaseTechnique):
    TECHNIQUE_ID   = "T1550.002"
    TECHNIQUE_NAME = "Use Alternate Authentication Material: Pass the Hash"
    TACTIC         = "lateral_movement"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.CRITICAL

    def execute(self, context: dict[str, Any]) -> AttackStep:
        src_host  = context.get("initial_access_host", self._fake_hostname())
        tgt_host  = self._fake_hostname("DC")
        fake_hash = "aad3b435b51404eeaad3b435b51404ee:" + "".join(
            random.choices("0123456789abcdef", k=32)
        )
        user      = random.choice(["Administrator", "Domain Admin", self._fake_username()])
        success   = self._did_succeed()

        if success:
            context.setdefault("compromised_hosts", []).append(tgt_host)
            context["domain_admin_obtained"] = True

        return self._make_step(
            description=f"Pass-the-Hash: using NTLM hash of '{user}' to authenticate to {tgt_host} — {'success — domain admin access' if success else 'hash rejected'}",
            source_host=src_host, target_host=tgt_host, success=success,
            severity=Severity.CRITICAL.value,
            extra_data={
                "username": user, "ntlm_hash": fake_hash[:20] + "...",
                "tool": "Mimikatz / Impacket", "target": tgt_host,
            },
        )


class PassTheTicket(BaseTechnique):
    TECHNIQUE_ID   = "T1550.003"
    TECHNIQUE_NAME = "Use Alternate Authentication Material: Pass the Ticket"
    TACTIC         = "lateral_movement"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.CRITICAL

    def execute(self, context: dict[str, Any]) -> AttackStep:
        src_host = context.get("initial_access_host", self._fake_hostname())
        tgt_host = self._fake_hostname("SRV")
        user     = context.get("initial_access_user", self._fake_username())
        ticket   = f"krbtgt/{random.randint(1000,9999)}" if random.random() < 0.5 else f"cifs/{tgt_host}"
        success  = self._did_succeed()

        if success:
            context.setdefault("compromised_hosts", []).append(tgt_host)

        return self._make_step(
            description=f"Pass-the-Ticket: injecting Kerberos TGT for '{user}' to access {tgt_host}",
            source_host=src_host, target_host=tgt_host, success=success,
            severity=Severity.CRITICAL.value,
            extra_data={
                "ticket_type": "Golden Ticket" if "krbtgt" in ticket else "Silver Ticket",
                "spn": ticket, "user": user, "tool": "Rubeus / Mimikatz",
            },
        )
