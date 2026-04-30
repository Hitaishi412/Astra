"""
App-wide constants — severity levels, kill chain phases, role types, etc.
Import with: from config.constants import Severity, KillChainPhase, ...
"""

from enum import Enum


# ---------------------------------------------------------------------------
# User roles
# ---------------------------------------------------------------------------
class Role(str, Enum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    FULL_SPECTRUM = "full_spectrum"


# ---------------------------------------------------------------------------
# Session status
# ---------------------------------------------------------------------------
class SessionStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"


# ---------------------------------------------------------------------------
# Kill chain phases (Lockheed Martin Cyber Kill Chain + ATT&CK mapping)
# ---------------------------------------------------------------------------
class KillChainPhase(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


# ---------------------------------------------------------------------------
# Alert severity levels
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Alert triage status
# ---------------------------------------------------------------------------
class TriageStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"
    RESOLVED = "resolved"


# ---------------------------------------------------------------------------
# Log source types
# ---------------------------------------------------------------------------
class LogSource(str, Enum):
    WINDOWS_EVENT = "windows_event"
    LINUX_SYSLOG = "linux_syslog"
    NETWORK_FLOW = "network_flow"
    CLOUD_AUDIT = "cloud_audit"
    APPLICATION = "application"
    ENDPOINT_EDR = "endpoint_edr"


# ---------------------------------------------------------------------------
# Difficulty levels
# ---------------------------------------------------------------------------
class Difficulty(str, Enum):
    BEGINNER = "beginner"       # Noisy attacks, obvious IOCs
    MEDIUM = "medium"           # Some evasion, moderate noise
    HARD = "hard"               # Stealthy attacks, high noise ratio
    EXPERT = "expert"           # APT-level evasion, minimal IOCs


# ---------------------------------------------------------------------------
# Report types
# ---------------------------------------------------------------------------
class ReportType(str, Enum):
    PENTEST = "pentest"             # Red team penetration test report
    INCIDENT = "incident"           # Blue team incident report
    DEBRIEF = "debrief"             # Auto-generated after-action summary


# ---------------------------------------------------------------------------
# MITRE ATT&CK tactics (Enterprise)
# ---------------------------------------------------------------------------
class MitreTactic(str, Enum):
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


# ---------------------------------------------------------------------------
# WebSocket channel names
# ---------------------------------------------------------------------------
class Channel(str, Enum):
    LOGS = "channel:logs"
    ALERTS = "channel:alerts"
    SCORES = "channel:scores"
    CONTROL = "channel:control"
    ATTACK_STATUS = "channel:attack_status"


# ---------------------------------------------------------------------------
# Scoring thresholds
# ---------------------------------------------------------------------------
SCORE_THRESHOLDS = {
    "excellent": 90,
    "good": 75,
    "average": 55,
    "needs_improvement": 35,
    "poor": 0,
}

# ---------------------------------------------------------------------------
# Risk score range
# ---------------------------------------------------------------------------
RISK_SCORE_MIN = 0
RISK_SCORE_MAX = 100
