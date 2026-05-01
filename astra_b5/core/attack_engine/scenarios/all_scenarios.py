"""
core/attack_engine/scenarios/ransomware.py
core/attack_engine/scenarios/apt_espionage.py
core/attack_engine/scenarios/insider_threat.py
core/attack_engine/scenarios/phishing_chain.py
core/attack_engine/scenarios/supply_chain.py

All 5 scenario implementations in one file for clarity.
Each maps to an entry in SCENARIO_REGISTRY (api/schemas/scenario.py).
"""

from __future__ import annotations

from config.constants import KillChainPhase, Difficulty
from core.attack_engine.scenarios.base_scenario import BaseScenario
from core.attack_engine.techniques import (
    reconnaissance, initial_access, execution,
    persistence, privilege_escalation, lateral_movement,
    exfiltration,
)
# Defense evasion + impact live in exfiltration.py module
from core.attack_engine.techniques.exfiltration import (
    LogClearing, ObfuscatedFiles, TimeStomp,
    RansomwareEncryption, DataDestruction,
    DNSTunnelExfil, C2ChannelExfil, CloudStorageExfil,
)


# ─── 1. Ransomware ────────────────────────────────────────────────────────────

class RansomwareScenario(BaseScenario):
    SCENARIO_ID = "ransomware"
    NAME        = "Ransomware Outbreak"
    DESCRIPTION = "Full ransomware kill chain: phishing → macro → persistence → lateral → encrypt."
    PHASES      = [
        KillChainPhase.RECONNAISSANCE,
        KillChainPhase.DELIVERY,
        KillChainPhase.EXPLOITATION,
        KillChainPhase.INSTALLATION,
        KillChainPhase.COMMAND_AND_CONTROL,
        KillChainPhase.ACTIONS_ON_OBJECTIVES,
    ]

    def _build_phase_techniques(self):
        d = self.difficulty
        return {
            KillChainPhase.RECONNAISSANCE:       [reconnaissance.ActivePortScan(d)],
            KillChainPhase.DELIVERY:             [initial_access.SpearphishingAttachment(d)],
            KillChainPhase.EXPLOITATION:         [initial_access.ValidAccounts(d),
                                                   execution.PowerShellExecution(d)],
            KillChainPhase.INSTALLATION:         [persistence.RegistryRunKey(d),
                                                   persistence.ScheduledTask(d),
                                                   ObfuscatedFiles(d)],
            KillChainPhase.COMMAND_AND_CONTROL:  [lateral_movement.RDPLateralMovement(d),
                                                   lateral_movement.PassTheHash(d)],
            KillChainPhase.ACTIONS_ON_OBJECTIVES:[C2ChannelExfil(d),
                                                   LogClearing(d),
                                                   RansomwareEncryption(d)],
        }


# ─── 2. APT Espionage ─────────────────────────────────────────────────────────

class APTEspionageScenario(BaseScenario):
    SCENARIO_ID = "apt_espionage"
    NAME        = "APT Espionage Campaign"
    DESCRIPTION = "Slow, stealthy APT: supply chain → covert C2 → DNS exfil over weeks."
    PHASES      = [
        KillChainPhase.RECONNAISSANCE,
        KillChainPhase.DELIVERY,
        KillChainPhase.EXPLOITATION,
        KillChainPhase.INSTALLATION,
        KillChainPhase.COMMAND_AND_CONTROL,
        KillChainPhase.ACTIONS_ON_OBJECTIVES,
    ]

    def _build_phase_techniques(self):
        d = self.difficulty
        return {
            KillChainPhase.RECONNAISSANCE:       [reconnaissance.OSINTCredentialHarvest(d),
                                                   reconnaissance.VulnerabilityScanning(d)],
            KillChainPhase.DELIVERY:             [initial_access.SoftwareSupplyChain(d)],
            KillChainPhase.EXPLOITATION:         [initial_access.ValidAccounts(d),
                                                   execution.CMDExecution(d)],
            KillChainPhase.INSTALLATION:         [persistence.ScheduledTask(d),
                                                   ObfuscatedFiles(d),
                                                   TimeStomp(d)],
            KillChainPhase.COMMAND_AND_CONTROL:  [lateral_movement.PassTheTicket(d),
                                                   lateral_movement.SMBAdminShares(d)],
            KillChainPhase.ACTIONS_ON_OBJECTIVES:[DNSTunnelExfil(d),
                                                   LogClearing(d)],
        }


# ─── 3. Insider Threat ────────────────────────────────────────────────────────

class InsiderThreatScenario(BaseScenario):
    SCENARIO_ID = "insider_threat"
    NAME        = "Malicious Insider"
    DESCRIPTION = "Disgruntled employee abuses legitimate access to steal and destroy data."
    PHASES      = [
        KillChainPhase.RECONNAISSANCE,
        KillChainPhase.ACTIONS_ON_OBJECTIVES,
    ]

    def _build_phase_techniques(self):
        d = self.difficulty
        return {
            KillChainPhase.RECONNAISSANCE:       [reconnaissance.ActivePortScan(d)],
            KillChainPhase.ACTIONS_ON_OBJECTIVES:[CloudStorageExfil(d),
                                                   C2ChannelExfil(d),
                                                   LogClearing(d),
                                                   DataDestruction(d)],
        }


# ─── 4. Phishing Chain ────────────────────────────────────────────────────────

class PhishingChainScenario(BaseScenario):
    SCENARIO_ID = "phishing_chain"
    NAME        = "Phishing → Credential Harvest → Pivot"
    DESCRIPTION = "Targeted phish → credential steal → VPN access → Mimikatz → lateral."
    PHASES      = [
        KillChainPhase.RECONNAISSANCE,
        KillChainPhase.DELIVERY,
        KillChainPhase.EXPLOITATION,
        KillChainPhase.COMMAND_AND_CONTROL,
        KillChainPhase.ACTIONS_ON_OBJECTIVES,
    ]

    def _build_phase_techniques(self):
        d = self.difficulty
        return {
            KillChainPhase.RECONNAISSANCE:       [reconnaissance.OSINTCredentialHarvest(d)],
            KillChainPhase.DELIVERY:             [initial_access.SpearphishingLink(d)],
            KillChainPhase.EXPLOITATION:         [initial_access.ValidAccounts(d),
                                                   execution.PowerShellExecution(d),
                                                   privilege_escalation.TokenImpersonation(d)],
            KillChainPhase.COMMAND_AND_CONTROL:  [lateral_movement.PassTheHash(d),
                                                   lateral_movement.RDPLateralMovement(d)],
            KillChainPhase.ACTIONS_ON_OBJECTIVES:[C2ChannelExfil(d),
                                                   LogClearing(d)],
        }


# ─── 5. Supply Chain ─────────────────────────────────────────────────────────

class SupplyChainScenario(BaseScenario):
    SCENARIO_ID = "supply_chain"
    NAME        = "Supply Chain Compromise"
    DESCRIPTION = "Trojanized package auto-installs backdoor → long-term covert collection."
    PHASES      = [
        KillChainPhase.DELIVERY,
        KillChainPhase.EXPLOITATION,
        KillChainPhase.INSTALLATION,
        KillChainPhase.COMMAND_AND_CONTROL,
        KillChainPhase.ACTIONS_ON_OBJECTIVES,
    ]

    def _build_phase_techniques(self):
        d = self.difficulty
        return {
            KillChainPhase.DELIVERY:             [initial_access.SoftwareSupplyChain(d)],
            KillChainPhase.EXPLOITATION:         [initial_access.ExploitPublicApp(d),
                                                   execution.WMIExecution(d)],
            KillChainPhase.INSTALLATION:         [persistence.CreateLocalAccount(d),
                                                   persistence.ScheduledTask(d),
                                                   ObfuscatedFiles(d)],
            KillChainPhase.COMMAND_AND_CONTROL:  [lateral_movement.SMBAdminShares(d)],
            KillChainPhase.ACTIONS_ON_OBJECTIVES:[C2ChannelExfil(d),
                                                   DNSTunnelExfil(d),
                                                   LogClearing(d)],
        }


# ─── Registry ─────────────────────────────────────────────────────────────────

SCENARIO_MAP: dict[str, type[BaseScenario]] = {
    "ransomware":     RansomwareScenario,
    "apt_espionage":  APTEspionageScenario,
    "insider_threat": InsiderThreatScenario,
    "phishing_chain": PhishingChainScenario,
    "supply_chain":   SupplyChainScenario,
}
