"""
core/attack_engine/techniques/exfiltration.py
core/attack_engine/techniques/defense_evasion.py
core/attack_engine/techniques/impact.py
— all in one file, separated by class.
"""
from __future__ import annotations
import random
from typing import Any
from config.constants import KillChainPhase, Severity
from core.attack_engine.techniques.base import BaseTechnique, AttackStep


# ─── Exfiltration ─────────────────────────────────────────────────────────────

class DNSTunnelExfil(BaseTechnique):
    """T1071.004 — Exfiltrate data hidden in DNS queries."""
    TECHNIQUE_ID   = "T1071.004"
    TECHNIQUE_NAME = "Application Layer Protocol: DNS"
    TACTIC         = "exfiltration"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.HIGH

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host    = context.get("current_host", context.get("initial_access_host", self._fake_hostname()))
        c2      = f"tunnel.{self._fake_ip(False).replace('.', '-')}.exfil.io"
        size_kb = random.randint(50, 5000)
        success = self._did_succeed()
        if success:
            context["exfil_bytes"] = size_kb * 1024
        return self._make_step(
            description=f"DNS tunneling exfiltration from {host} → {c2} — {size_kb}KB {'sent' if success else 'blocked'}",
            source_host=host, target_host=c2, success=success,
            extra_data={"c2_domain": c2, "data_size_kb": size_kb, "protocol": "DNS TXT/A records",
                        "tool": "iodine / dnscat2", "encoded": True},
        )


class C2ChannelExfil(BaseTechnique):
    """T1041 — Exfiltrate over established C2 channel."""
    TECHNIQUE_ID   = "T1041"
    TECHNIQUE_NAME = "Exfiltration Over C2 Channel"
    TACTIC         = "exfiltration"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.CRITICAL

    DATA_TYPES = ["Active Directory dump", "SAM database", "customer PII records",
                  "source code repository", "financial records", "HR database"]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host    = context.get("current_host", context.get("initial_access_host", self._fake_hostname()))
        c2_ip   = self._fake_ip(False)
        data    = random.choice(self.DATA_TYPES)
        size_mb = random.randint(10, 2000)
        success = self._did_succeed()
        if success:
            context["data_stolen"] = data
            context["exfil_bytes"] = size_mb * 1024 * 1024
        return self._make_step(
            description=f"C2 exfiltration: {data} ({size_mb}MB) from {host} → {c2_ip} — {'complete' if success else 'interrupted by DLP'}",
            source_host=host, target_host=c2_ip, success=success,
            severity=Severity.CRITICAL.value,
            extra_data={"c2_server": c2_ip, "data_type": data, "size_mb": size_mb,
                        "encrypted": self.difficulty in ("hard", "expert"), "port": random.choice([443, 8443, 4444])},
        )


class CloudStorageExfil(BaseTechnique):
    """T1567.002 — Upload data to attacker-controlled cloud storage."""
    TECHNIQUE_ID   = "T1567.002"
    TECHNIQUE_NAME = "Exfiltration to Cloud Storage"
    TACTIC         = "exfiltration"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.HIGH

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host     = context.get("initial_access_host", self._fake_hostname())
        service  = random.choice(["Dropbox", "Google Drive", "OneDrive personal", "Mega.nz", "AWS S3 (attacker bucket)"])
        size_gb  = round(random.uniform(0.1, 15.0), 2)
        success  = self._did_succeed()
        return self._make_step(
            description=f"Data uploaded to {service} from {host}: {size_gb}GB {'completed' if success else 'blocked by firewall policy'}",
            source_host=host, target_host=service, success=success,
            extra_data={"service": service, "size_gb": size_gb, "method": "HTTPS PUT", "chunked": size_gb > 1},
        )


# ─── Defense Evasion ─────────────────────────────────────────────────────────

class LogClearing(BaseTechnique):
    """T1070.001 — Clear Windows event logs to destroy forensic evidence."""
    TECHNIQUE_ID   = "T1070.001"
    TECHNIQUE_NAME = "Indicator Removal: Clear Windows Event Logs"
    TACTIC         = "defense_evasion"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.HIGH

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host    = context.get("current_host", context.get("initial_access_host", self._fake_hostname()))
        logs    = random.sample(["Security", "System", "Application", "PowerShell", "Sysmon"], k=random.randint(2, 5))
        success = self._did_succeed()
        return self._make_step(
            description=f"Event log clearing on {host}: {', '.join(logs)} — {'cleared' if success else 'permission denied'}",
            source_host=host, target_host=host, success=success,
            extra_data={"logs_cleared": logs, "command": "wevtutil cl " + " ".join(logs),
                        "forensic_impact": "HIGH" if success else "NONE"},
        )


class ObfuscatedFiles(BaseTechnique):
    """T1027 — Obfuscate payloads to evade signature detection."""
    TECHNIQUE_ID   = "T1027"
    TECHNIQUE_NAME = "Obfuscated Files or Information"
    TACTIC         = "defense_evasion"
    PHASE          = KillChainPhase.INSTALLATION
    BASE_SEVERITY  = Severity.MEDIUM

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host    = context.get("initial_access_host", self._fake_hostname())
        method  = random.choice(["Base64 encoding", "XOR encryption", "PowerShell string concatenation",
                                  "Steganography in PNG", "AMSI bypass via reflection"])
        success = self._did_succeed()
        return self._make_step(
            description=f"Payload obfuscation on {host}: {method} — {'AV evaded' if success else 'detected by AV'}",
            source_host=host, target_host=host, success=success,
            extra_data={"method": method, "av_evaded": success, "tool": "Invoke-Obfuscation"},
        )


class TimeStomp(BaseTechnique):
    """T1070.006 — Modify file timestamps to confuse timeline analysis."""
    TECHNIQUE_ID   = "T1070.006"
    TECHNIQUE_NAME = "Indicator Removal: Timestomping"
    TACTIC         = "defense_evasion"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.MEDIUM

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host  = context.get("initial_access_host", self._fake_hostname())
        files = [f"C:\\Users\\Public\\{f}" for f in
                 random.sample(["svchost32.exe", "update.dll", "helper.ps1", "data.zip"], k=2)]
        success = self._did_succeed()
        return self._make_step(
            description=f"Timestomping {len(files)} files on {host} to match system files — {'complete' if success else 'failed'}",
            source_host=host, target_host=host, success=success,
            extra_data={"files": files, "new_timestamp": "2019-06-15T08:00:00Z", "tool": "Meterpreter timestomp"},
        )


# ─── Impact ───────────────────────────────────────────────────────────────────

class RansomwareEncryption(BaseTechnique):
    """T1486 — Encrypt files and demand ransom."""
    TECHNIQUE_ID   = "T1486"
    TECHNIQUE_NAME = "Data Encrypted for Impact"
    TACTIC         = "impact"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.CRITICAL

    FAMILIES = ["LockBit 3.0", "BlackCat/ALPHV", "Conti", "REvil", "Hive", "Cl0p"]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        hosts    = context.get("compromised_hosts", [context.get("initial_access_host", self._fake_hostname())])
        family   = random.choice(self.FAMILIES)
        files    = random.randint(10000, 500000)
        ext      = "." + "".join(random.choices("abcdefghijklmnop", k=5))
        ransom   = random.randint(50000, 5000000)
        success  = self._did_succeed()
        return self._make_step(
            description=(
                f"{family} ransomware deployed across {len(hosts)} host(s). "
                f"{'Encrypted ' + str(files) + ' files with extension ' + ext + '. Ransom demand: $' + str(ransom) if success else 'Execution blocked by EDR.'}"
            ),
            source_host=hosts[0] if hosts else self._fake_hostname(),
            target_host=f"{len(hosts)} hosts",
            success=success,
            severity=Severity.CRITICAL.value,
            extra_data={
                "ransomware_family": family, "files_encrypted": files if success else 0,
                "extension": ext, "ransom_usd": ransom, "hosts_affected": len(hosts),
                "note_dropped": "README_DECRYPT.txt",
                "exfil_before_encrypt": context.get("data_stolen") is not None,
            },
        )


class DataDestruction(BaseTechnique):
    """T1485 — Wipe critical data / MBR to cause maximum disruption."""
    TECHNIQUE_ID   = "T1485"
    TECHNIQUE_NAME = "Data Destruction"
    TACTIC         = "impact"
    PHASE          = KillChainPhase.ACTIONS_ON_OBJECTIVES
    BASE_SEVERITY  = Severity.CRITICAL

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host    = context.get("initial_access_host", self._fake_hostname())
        method  = random.choice(["MBR wipe", "sdelete recursive", "format C:", "dd if=/dev/zero of=/dev/sda"])
        success = self._did_succeed()
        return self._make_step(
            description=f"Destructive wiper on {host}: {method} — {'system destroyed' if success else 'blocked'}",
            source_host=host, target_host=host, success=success,
            severity=Severity.CRITICAL.value,
            extra_data={"method": method, "recoverable": False, "tool": "custom wiper"},
        )
