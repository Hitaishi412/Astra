"""
core/attack_engine/techniques/reconnaissance.py
────────────────────────────────────────────────
MITRE ATT&CK Reconnaissance techniques.

Techniques implemented:
  - T1595.001  Active Scanning: Scanning IP Blocks
  - T1595.002  Active Scanning: Vulnerability Scanning
  - T1592.002  Gather Victim Host Information: Software
  - T1589.001  Gather Victim Identity Information: Credentials
  - T1590.001  Gather Victim Network Information: Domain Properties
"""

from __future__ import annotations

import random
from typing import Any

from config.constants import KillChainPhase, Severity, Difficulty
from core.attack_engine.techniques.base import BaseTechnique, AttackStep


class ActivePortScan(BaseTechnique):
    """T1595.001 — Attacker scans the target IP range for open ports."""

    TECHNIQUE_ID   = "T1595.001"
    TECHNIQUE_NAME = "Active Scanning: Scanning IP Blocks"
    TACTIC         = "reconnaissance"
    PHASE          = KillChainPhase.RECONNAISSANCE
    BASE_SEVERITY  = Severity.LOW

    # Common ports attackers probe first
    TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
                 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        target_ip    = context.get("target_ip", self._fake_ip())
        open_ports   = random.sample(self.TOP_PORTS, k=random.randint(2, 6))
        scan_type    = "SYN" if self.difficulty in (Difficulty.HARD, Difficulty.EXPERT) else "TCP Connect"

        context.setdefault("open_ports", open_ports)
        context.setdefault("target_ip", target_ip)

        return self._make_step(
            description=(
                f"Performed {scan_type} port scan against {target_ip}/24. "
                f"Discovered {len(open_ports)} open ports: {open_ports}."
            ),
            source_host = self._fake_ip(internal=False),
            target_host = target_ip,
            success     = True,
            extra_data  = {
                "scan_type":    scan_type,
                "target_range": f"{target_ip}/24",
                "open_ports":   open_ports,
                "scan_tool":    "nmap" if self.difficulty != Difficulty.EXPERT else "masscan (custom)",
                "timing":       "T4 aggressive" if self.difficulty == Difficulty.BEGINNER else "T2 polite",
            },
        )


class VulnerabilityScanning(BaseTechnique):
    """T1595.002 — Attacker probes discovered services for known CVEs."""

    TECHNIQUE_ID   = "T1595.002"
    TECHNIQUE_NAME = "Active Scanning: Vulnerability Scanning"
    TACTIC         = "reconnaissance"
    PHASE          = KillChainPhase.RECONNAISSANCE
    BASE_SEVERITY  = Severity.MEDIUM

    VULNS = [
        ("CVE-2021-44228", "Log4Shell", "Apache Log4j", 10.0),
        ("CVE-2021-34527", "PrintNightmare", "Windows Print Spooler", 8.8),
        ("CVE-2017-0144",  "EternalBlue", "SMBv1", 9.3),
        ("CVE-2019-19781", "Citrix ADC path traversal", "Citrix ADC", 9.8),
        ("CVE-2020-1472",  "Zerologon", "Netlogon", 10.0),
        ("CVE-2022-30190", "Follina", "MSDT / Office", 7.8),
    ]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        target_ip = context.get("target_ip", self._fake_ip())
        cve_id, vuln_name, service, cvss = random.choice(self.VULNS)
        found = self._did_succeed()

        if found:
            context.setdefault("cve_found", cve_id)
            context.setdefault("vuln_service", service)

        return self._make_step(
            description=(
                f"Vulnerability scan against {target_ip} — "
                f"{'found exploitable ' + vuln_name + ' (' + cve_id + ')' if found else 'no critical vulns found, trying next vector'}."
            ),
            source_host = self._fake_ip(internal=False),
            target_host = target_ip,
            success     = found,
            severity    = Severity.HIGH.value if found else Severity.LOW.value,
            extra_data  = {
                "scanner":      "Nessus" if self.difficulty == Difficulty.BEGINNER else "custom nuclei templates",
                "cve_checked":  cve_id,
                "vuln_name":    vuln_name,
                "service":      service,
                "cvss_score":   cvss,
                "exploitable":  found,
            },
        )


class OSINTCredentialHarvest(BaseTechnique):
    """T1589.001 — Gather leaked credentials from public breach databases."""

    TECHNIQUE_ID   = "T1589.001"
    TECHNIQUE_NAME = "Gather Victim Identity Information: Credentials"
    TACTIC         = "reconnaissance"
    PHASE          = KillChainPhase.RECONNAISSANCE
    BASE_SEVERITY  = Severity.MEDIUM

    BREACH_SOURCES = ["HaveIBeenPwned", "DeHashed", "Snusbase", "IntelX", "dark web paste"]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        domain      = context.get("target_domain", "corp.internal")
        source      = random.choice(self.BREACH_SOURCES)
        count       = random.randint(12, 850)
        username    = self._fake_username()
        success     = self._did_succeed()

        if success:
            context.setdefault("harvested_credentials", []).append(username)

        return self._make_step(
            description=(
                f"OSINT credential harvesting for @{domain} via {source}. "
                f"{'Found ' + str(count) + ' credential pairs including ' + username if success else 'No fresh credentials found'}."
            ),
            source_host = None,
            target_host = None,
            success     = success,
            extra_data  = {
                "source":           source,
                "target_domain":    domain,
                "credentials_found": count if success else 0,
                "sample_username":  username if success else None,
                "method":           "automated breach search",
            },
        )
