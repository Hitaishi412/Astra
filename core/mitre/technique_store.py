"""
core/mitre/technique_store.py
──────────────────────────────
In-process cache and query layer for the MITRE ATT&CK Enterprise matrix.

Reads from core/mitre/data/enterprise_attack.json (written by scripts/seed_mitre.py).
Falls back to a compact built-in stub so the system works offline — the stub
covers every technique Block 2 uses so coverage tracking never breaks.

Public interface
────────────────
    store = TechniqueStore()

    t = store.get("T1059.001")
    # → {"id": "T1059.001", "name": "PowerShell", "tactics": [...], ...}

    store.get_many(["T1059.001", "T1021.001"])
    store.by_tactic("initial_access")
    store.tactic_for_technique("T1566.001")
    store.exists("T1059.001")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

# ─── Paths ────────────────────────────────────────────────────────────────────

_DATA_DIR  = Path(__file__).parent / "data"
_JSON_PATH = _DATA_DIR / "enterprise_attack.json"

# ─── Offline stub — every technique used in Block 2 ──────────────────────────
# Keyed by technique ID. Enough metadata for coverage + scoring to work
# without a network call or a seeded JSON file.

_BUILTIN_STUB: dict[str, dict] = {
    # Reconnaissance
    "T1595.001": {"id": "T1595.001", "name": "Active Scanning: Scanning IP Blocks",
                  "tactics": ["reconnaissance"], "platforms": ["Network"], "url": "https://attack.mitre.org/techniques/T1595/001/"},
    "T1595.002": {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning",
                  "tactics": ["reconnaissance"], "platforms": ["Network"], "url": "https://attack.mitre.org/techniques/T1595/002/"},
    "T1589.001": {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials",
                  "tactics": ["reconnaissance"], "platforms": ["PRE"], "url": "https://attack.mitre.org/techniques/T1589/001/"},
    "T1590.001": {"id": "T1590.001", "name": "Gather Victim Network Information: Domain Properties",
                  "tactics": ["reconnaissance"], "platforms": ["PRE"], "url": "https://attack.mitre.org/techniques/T1590/001/"},
    "T1592.002": {"id": "T1592.002", "name": "Gather Victim Host Information: Software",
                  "tactics": ["reconnaissance"], "platforms": ["PRE"], "url": "https://attack.mitre.org/techniques/T1592/002/"},

    # Initial Access
    "T1566.001": {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment",
                  "tactics": ["initial-access"], "platforms": ["Windows", "macOS", "Linux"],
                  "url": "https://attack.mitre.org/techniques/T1566/001/"},
    "T1566.002": {"id": "T1566.002", "name": "Phishing: Spearphishing Link",
                  "tactics": ["initial-access"], "platforms": ["Windows", "macOS", "Linux"],
                  "url": "https://attack.mitre.org/techniques/T1566/002/"},
    "T1190":     {"id": "T1190",     "name": "Exploit Public-Facing Application",
                  "tactics": ["initial-access"], "platforms": ["Windows", "Linux", "macOS", "Network"],
                  "url": "https://attack.mitre.org/techniques/T1190/"},
    "T1078":     {"id": "T1078",     "name": "Valid Accounts",
                  "tactics": ["initial-access", "persistence", "privilege-escalation", "defense-evasion"],
                  "platforms": ["Windows", "Linux", "macOS", "SaaS", "IaaS"],
                  "url": "https://attack.mitre.org/techniques/T1078/"},
    "T1195.002": {"id": "T1195.002", "name": "Supply Chain Compromise: Compromise Software Supply Chain",
                  "tactics": ["initial-access"], "platforms": ["Linux", "macOS", "Windows"],
                  "url": "https://attack.mitre.org/techniques/T1195/002/"},

    # Execution
    "T1059.001": {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell",
                  "tactics": ["execution"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1059/001/"},
    "T1059.003": {"id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell",
                  "tactics": ["execution"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1059/003/"},
    "T1059.006": {"id": "T1059.006", "name": "Command and Scripting Interpreter: Python",
                  "tactics": ["execution"], "platforms": ["Linux", "Windows", "macOS"],
                  "url": "https://attack.mitre.org/techniques/T1059/006/"},
    "T1047":     {"id": "T1047",     "name": "Windows Management Instrumentation",
                  "tactics": ["execution"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1047/"},

    # Persistence
    "T1547.001": {"id": "T1547.001", "name": "Boot/Logon Autostart Execution: Registry Run Keys",
                  "tactics": ["persistence", "privilege-escalation"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1547/001/"},
    "T1053.005": {"id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task",
                  "tactics": ["execution", "persistence", "privilege-escalation"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1053/005/"},
    "T1543.003": {"id": "T1543.003", "name": "Create or Modify System Process: Windows Service",
                  "tactics": ["persistence", "privilege-escalation"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1543/003/"},
    "T1136.001": {"id": "T1136.001", "name": "Create Account: Local Account",
                  "tactics": ["persistence"], "platforms": ["Linux", "macOS", "Windows"],
                  "url": "https://attack.mitre.org/techniques/T1136/001/"},

    # Privilege Escalation
    "T1134.001": {"id": "T1134.001", "name": "Access Token Manipulation: Token Impersonation/Theft",
                  "tactics": ["defense-evasion", "privilege-escalation"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1134/001/"},
    "T1548.003": {"id": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                  "tactics": ["privilege-escalation", "defense-evasion"], "platforms": ["Linux", "macOS"],
                  "url": "https://attack.mitre.org/techniques/T1548/003/"},

    # Lateral Movement
    "T1021.001": {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol",
                  "tactics": ["lateral-movement"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1021/001/"},
    "T1021.002": {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares",
                  "tactics": ["lateral-movement"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1021/002/"},
    "T1550.002": {"id": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash",
                  "tactics": ["defense-evasion", "lateral-movement"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1550/002/"},
    "T1550.003": {"id": "T1550.003", "name": "Use Alternate Authentication Material: Pass the Ticket",
                  "tactics": ["defense-evasion", "lateral-movement"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1550/003/"},

    # Exfiltration
    "T1071.004": {"id": "T1071.004", "name": "Application Layer Protocol: DNS",
                  "tactics": ["command-and-control"], "platforms": ["Linux", "macOS", "Windows", "Network"],
                  "url": "https://attack.mitre.org/techniques/T1071/004/"},
    "T1041":     {"id": "T1041",     "name": "Exfiltration Over C2 Channel",
                  "tactics": ["exfiltration"], "platforms": ["Linux", "macOS", "Windows"],
                  "url": "https://attack.mitre.org/techniques/T1041/"},
    "T1567.002": {"id": "T1567.002", "name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
                  "tactics": ["exfiltration"], "platforms": ["Linux", "macOS", "Windows"],
                  "url": "https://attack.mitre.org/techniques/T1567/002/"},

    # Defense Evasion
    "T1070.001": {"id": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs",
                  "tactics": ["defense-evasion"], "platforms": ["Windows"],
                  "url": "https://attack.mitre.org/techniques/T1070/001/"},
    "T1027":     {"id": "T1027",     "name": "Obfuscated Files or Information",
                  "tactics": ["defense-evasion"], "platforms": ["Linux", "macOS", "Windows"],
                  "url": "https://attack.mitre.org/techniques/T1027/"},
    "T1070.006": {"id": "T1070.006", "name": "Indicator Removal: Timestomping",
                  "tactics": ["defense-evasion"], "platforms": ["Linux", "macOS", "Windows"],
                  "url": "https://attack.mitre.org/techniques/T1070/006/"},

    # Impact
    "T1486":     {"id": "T1486",     "name": "Data Encrypted for Impact",
                  "tactics": ["impact"], "platforms": ["Linux", "macOS", "Windows", "IaaS"],
                  "url": "https://attack.mitre.org/techniques/T1486/"},
    "T1485":     {"id": "T1485",     "name": "Data Destruction",
                  "tactics": ["impact"], "platforms": ["Linux", "macOS", "Windows", "IaaS"],
                  "url": "https://attack.mitre.org/techniques/T1485/"},
}


class TechniqueStore:
    """
    Query layer over the MITRE ATT&CK Enterprise matrix.

    Loads enterprise_attack.json on first access; falls back to the
    built-in stub when the file is absent (e.g. before seed_mitre.py runs).
    """

    def __init__(self) -> None:
        self._techniques: dict[str, dict] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if _JSON_PATH.exists():
            try:
                with open(_JSON_PATH, encoding="utf-8") as fh:
                    data = json.load(fh)
                self._techniques = data.get("techniques", {})
            except Exception:
                pass  # fall through to stub
        # Always merge stub so Block-2 techniques are always resolvable
        for tid, info in _BUILTIN_STUB.items():
            self._techniques.setdefault(tid, info)
        self._loaded = True

    # ── Lookups ───────────────────────────────────────────────────────────────

    def get(self, technique_id: str) -> Optional[dict[str, Any]]:
        """Return the technique dict or None if unknown."""
        self._ensure_loaded()
        return self._techniques.get(technique_id.upper()) or self._techniques.get(technique_id)

    def get_many(self, technique_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Return {id: info} for each id that exists."""
        return {tid: info for tid in technique_ids if (info := self.get(tid))}

    def exists(self, technique_id: str) -> bool:
        return self.get(technique_id) is not None

    def tactic_for_technique(self, technique_id: str) -> list[str]:
        """Return list of tactic names for a technique."""
        info = self.get(technique_id)
        return info.get("tactics", []) if info else []

    def by_tactic(self, tactic: str) -> list[dict]:
        """Return all techniques belonging to a tactic."""
        self._ensure_loaded()
        return [t for t in self._techniques.values() if tactic in t.get("tactics", [])]

    def all_techniques(self) -> dict[str, dict]:
        self._ensure_loaded()
        return dict(self._techniques)

    @property
    def total_count(self) -> int:
        self._ensure_loaded()
        return len(self._techniques)

    @property
    def is_seeded(self) -> bool:
        """True if the full enterprise_attack.json is present."""
        return _JSON_PATH.exists()


# ── Module-level singleton ────────────────────────────────────────────────────
technique_store = TechniqueStore()
