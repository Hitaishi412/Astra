"""
Pydantic schemas for scenario endpoints.
Scenarios are defined in code (not DB) — this is the registry.
"""

from __future__ import annotations

from pydantic import BaseModel


class ScenarioResponse(BaseModel):
    """Response body for a single scenario."""
    id: str
    name: str
    description: str
    difficulty_range: list[str]
    kill_chain_phases: list[str]
    mitre_techniques: list[str]
    estimated_duration_minutes: int


# ---------------------------------------------------------------------------
# Scenario registry — add new scenarios here
# ---------------------------------------------------------------------------
SCENARIO_REGISTRY: dict[str, dict] = {
    "ransomware": {
        "id": "ransomware",
        "name": "Ransomware Outbreak",
        "description": (
            "A full ransomware attack chain: initial phishing email delivers a macro-enabled "
            "document, establishes persistence, escalates privileges, moves laterally across "
            "the network, and encrypts critical files. The attacker demands payment via a "
            "ransom note dropped on every affected machine."
        ),
        "difficulty_range": ["beginner", "medium", "hard", "expert"],
        "kill_chain_phases": [
            "reconnaissance", "delivery", "exploitation",
            "installation", "command_and_control", "actions_on_objectives",
        ],
        "mitre_techniques": [
            "T1566.001", "T1059.001", "T1547.001", "T1078",
            "T1486", "T1071.001", "T1048", "T1070.004",
        ],
        "estimated_duration_minutes": 30,
    },
    "apt_espionage": {
        "id": "apt_espionage",
        "name": "APT Espionage Campaign",
        "description": (
            "A slow-and-quiet advanced persistent threat. The attacker gains initial access "
            "through a compromised supply chain dependency, establishes a covert C2 channel, "
            "conducts internal reconnaissance over days, and exfiltrates sensitive documents "
            "through DNS tunneling — all while actively evading detection."
        ),
        "difficulty_range": ["medium", "hard", "expert"],
        "kill_chain_phases": [
            "reconnaissance", "weaponization", "delivery", "exploitation",
            "installation", "command_and_control", "actions_on_objectives",
        ],
        "mitre_techniques": [
            "T1195.002", "T1059.003", "T1053.005", "T1087.002",
            "T1018", "T1071.004", "T1048.003", "T1027",
        ],
        "estimated_duration_minutes": 45,
    },
    "insider_threat": {
        "id": "insider_threat",
        "name": "Malicious Insider",
        "description": (
            "A disgruntled employee with legitimate access abuses their credentials to "
            "access sensitive databases, stages data to a personal cloud storage account, "
            "and covers their tracks by modifying audit logs. No malware involved — "
            "detection relies entirely on behavioral anomalies."
        ),
        "difficulty_range": ["medium", "hard", "expert"],
        "kill_chain_phases": [
            "reconnaissance", "actions_on_objectives",
        ],
        "mitre_techniques": [
            "T1078.002", "T1083", "T1005", "T1567.002",
            "T1070.001", "T1529",
        ],
        "estimated_duration_minutes": 25,
    },
    "phishing_chain": {
        "id": "phishing_chain",
        "name": "Phishing → Credential Harvest → Pivot",
        "description": (
            "A targeted spearphishing campaign delivers a credential harvesting page. "
            "Stolen credentials are used to access the VPN, then the attacker pivots "
            "through internal systems using legitimate tools, harvesting more credentials "
            "via Mimikatz-style memory dumps."
        ),
        "difficulty_range": ["beginner", "medium", "hard"],
        "kill_chain_phases": [
            "reconnaissance", "delivery", "exploitation",
            "command_and_control", "actions_on_objectives",
        ],
        "mitre_techniques": [
            "T1566.002", "T1056.001", "T1078", "T1021.001",
            "T1003.001", "T1550.002",
        ],
        "estimated_duration_minutes": 30,
    },
    "supply_chain": {
        "id": "supply_chain",
        "name": "Supply Chain Compromise",
        "description": (
            "An attacker compromises a trusted third-party software update mechanism. "
            "A trojanized update is pushed to the target organization, establishing a "
            "backdoor that blends in with legitimate software behavior. The attacker "
            "uses this access for long-term data collection."
        ),
        "difficulty_range": ["hard", "expert"],
        "kill_chain_phases": [
            "weaponization", "delivery", "exploitation",
            "installation", "command_and_control", "actions_on_objectives",
        ],
        "mitre_techniques": [
            "T1195.002", "T1059.006", "T1543.003", "T1105",
            "T1071.001", "T1005", "T1041",
        ],
        "estimated_duration_minutes": 40,
    },
}
