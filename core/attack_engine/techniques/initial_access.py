"""
core/attack_engine/techniques/initial_access.py
────────────────────────────────────────────────
MITRE ATT&CK Initial Access techniques.

Techniques implemented:
  - T1566.001  Phishing: Spearphishing Attachment
  - T1566.002  Phishing: Spearphishing Link
  - T1190      Exploit Public-Facing Application
  - T1078      Valid Accounts
  - T1195.002  Supply Chain Compromise: Compromise Software Supply Chain
"""

from __future__ import annotations

import random
from typing import Any

from config.constants import KillChainPhase, Severity
from core.attack_engine.techniques.base import BaseTechnique, AttackStep


class SpearphishingAttachment(BaseTechnique):
    """T1566.001 — Malicious macro-enabled document delivered by email."""

    TECHNIQUE_ID   = "T1566.001"
    TECHNIQUE_NAME = "Phishing: Spearphishing Attachment"
    TACTIC         = "initial_access"
    PHASE          = KillChainPhase.DELIVERY
    BASE_SEVERITY  = Severity.HIGH

    LURES = [
        ("Invoice_Q4_{year}.xlsm",    "Accounting",  "invoice payment overdue"),
        ("HR_Policy_Update.docm",      "HR",          "mandatory read before Friday"),
        ("Shipment_Tracking_{id}.xlsm","Logistics",   "your package requires action"),
        ("Security_Audit_{year}.docm", "IT",          "immediate response required"),
        ("Salary_Revision_{year}.xlsm","Finance",     "confidential — please review"),
    ]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        lure_template, dept, subject_hint = random.choice(self.LURES)
        filename    = lure_template.format(year=2024, id=random.randint(10000, 99999))
        target_user = self._fake_username()
        target_host = context.get("target_ip", self._fake_hostname())
        opened      = self._did_succeed()

        if opened:
            context["initial_access_user"]  = target_user
            context["initial_access_host"]  = target_host if isinstance(target_host, str) else str(target_host)
            context["initial_access_method"] = "spearphishing_attachment"

        return self._make_step(
            description=(
                f"Spearphishing email sent to {target_user}@{context.get('target_domain', 'corp.internal')} "
                f"with attachment '{filename}' ({subject_hint}). "
                f"{'Macro executed — initial foothold established.' if opened else 'User did not open attachment.'}"
            ),
            source_host = self._fake_ip(internal=False),
            target_host = target_host,
            success     = opened,
            extra_data  = {
                "attachment":     filename,
                "target_user":    target_user,
                "target_dept":    dept,
                "subject":        subject_hint,
                "macro_executed": opened,
                "payload_type":   "VBA macro dropper",
                "c2_callback":    self._fake_ip(internal=False) if opened else None,
            },
        )


class SpearphishingLink(BaseTechnique):
    """T1566.002 — Credential harvesting via fake login page."""

    TECHNIQUE_ID   = "T1566.002"
    TECHNIQUE_NAME = "Phishing: Spearphishing Link"
    TACTIC         = "initial_access"
    PHASE          = KillChainPhase.DELIVERY
    BASE_SEVERITY  = Severity.HIGH

    FAKE_DOMAINS = [
        "corp-portal-secure.com", "login-internal-it.net",
        "hr-update-required.org", "vpn-access-renewal.com",
        "sharepoint-corp-doc.net",
    ]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        target_user   = self._fake_username()
        phishing_domain = random.choice(self.FAKE_DOMAINS)
        clicked       = self._did_succeed()
        creds_entered = clicked and random.random() < 0.70

        if creds_entered:
            context["harvested_credentials"] = context.get("harvested_credentials", [])
            context["harvested_credentials"].append(target_user)
            context["initial_access_user"]   = target_user
            context["initial_access_method"] = "credential_harvesting"

        return self._make_step(
            description=(
                f"Phishing link sent to {target_user} pointing to {phishing_domain}. "
                f"{'Link clicked and credentials entered — harvested password.' if creds_entered else 'Link clicked but no credentials submitted.' if clicked else 'User did not click link.'}"
            ),
            source_host = self._fake_ip(internal=False),
            target_host = None,
            success     = creds_entered,
            extra_data  = {
                "phishing_domain":  phishing_domain,
                "target_user":      target_user,
                "link_clicked":     clicked,
                "creds_harvested":  creds_entered,
                "hosting":          "bulletproof VPS",
                "ssl_cert":         "Let's Encrypt (legitimate-looking)",
            },
        )


class ExploitPublicApp(BaseTechnique):
    """T1190 — Exploit a vulnerability in an internet-facing service."""

    TECHNIQUE_ID   = "T1190"
    TECHNIQUE_NAME = "Exploit Public-Facing Application"
    TACTIC         = "initial_access"
    PHASE          = KillChainPhase.EXPLOITATION
    BASE_SEVERITY  = Severity.CRITICAL

    def execute(self, context: dict[str, Any]) -> AttackStep:
        target_ip  = context.get("target_ip", self._fake_ip())
        cve_id     = context.get("cve_found", "CVE-2021-44228")
        service    = context.get("vuln_service", "Apache Log4j")
        exploited  = self._did_succeed()

        if exploited:
            context["initial_access_host"]   = target_ip
            context["initial_access_method"] = "exploit"
            context["shell_obtained"]        = True

        return self._make_step(
            description=(
                f"Exploited {cve_id} ({service}) on {target_ip}. "
                f"{'Remote code execution achieved — shell obtained.' if exploited else 'Exploit failed — target may be patched.'}"
            ),
            source_host = self._fake_ip(internal=False),
            target_host = target_ip,
            success     = exploited,
            severity    = Severity.CRITICAL.value,
            extra_data  = {
                "cve_id":          cve_id,
                "service":         service,
                "exploit_type":    "RCE",
                "shell_type":      "reverse shell" if exploited else None,
                "shell_port":      random.choice([4444, 9001, 8443, 1337]) if exploited else None,
                "payload":         "meterpreter/reverse_tcp" if exploited else None,
            },
        )


class ValidAccounts(BaseTechnique):
    """T1078 — Use stolen or default credentials to log in legitimately."""

    TECHNIQUE_ID   = "T1078"
    TECHNIQUE_NAME = "Valid Accounts"
    TACTIC         = "initial_access"
    PHASE          = KillChainPhase.EXPLOITATION
    BASE_SEVERITY  = Severity.HIGH

    def execute(self, context: dict[str, Any]) -> AttackStep:
        username   = (
            context.get("harvested_credentials", [None])[0]
            or self._fake_username()
        )
        target_ip  = context.get("target_ip", self._fake_ip())
        service    = random.choice(["VPN", "OWA", "RDP", "SSH", "Citrix"])
        success    = self._did_succeed()

        if success:
            context["initial_access_user"]   = username
            context["initial_access_host"]   = target_ip
            context["initial_access_method"] = "valid_accounts"

        return self._make_step(
            description=(
                f"Authenticated to {service} at {target_ip} as '{username}' using harvested credentials. "
                f"{'Login successful — legitimate access established.' if success else 'Authentication failed — credentials may be stale or MFA blocked.'}"
            ),
            source_host = self._fake_ip(internal=False),
            target_host = target_ip,
            success     = success,
            extra_data  = {
                "username":       username,
                "service":        service,
                "auth_method":    "password",
                "mfa_bypassed":   False,
                "source_country": random.choice(["RU", "CN", "IR", "KP", "BR"]),
            },
        )


class SoftwareSupplyChain(BaseTechnique):
    """T1195.002 — Compromised package in software supply chain."""

    TECHNIQUE_ID   = "T1195.002"
    TECHNIQUE_NAME = "Supply Chain Compromise: Software Supply Chain"
    TACTIC         = "initial_access"
    PHASE          = KillChainPhase.DELIVERY
    BASE_SEVERITY  = Severity.CRITICAL

    PACKAGES = [
        ("node-fetch-extra", "npm",  "3.1.2"),
        ("requests-secure",  "pip",  "2.28.1"),
        ("log4j-core",       "maven","2.14.1"),
        ("lodash-utils",     "npm",  "4.17.19"),
        ("boto3-helper",     "pip",  "1.26.0"),
    ]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        pkg_name, pkg_mgr, pkg_ver = random.choice(self.PACKAGES)
        targets  = random.randint(3, 12)   # machines that auto-updated
        success  = self._did_succeed()

        if success:
            context["initial_access_method"] = "supply_chain"
            context["affected_hosts_count"]  = targets

        return self._make_step(
            description=(
                f"Trojanized {pkg_mgr} package '{pkg_name}@{pkg_ver}' pushed via compromised registry. "
                f"{'Package installed on ' + str(targets) + ' machines — backdoor active.' if success else 'Package flagged by package manager integrity check.'}"
            ),
            source_host = None,
            target_host = context.get("target_ip", "internal-network"),
            success     = success,
            severity    = Severity.CRITICAL.value,
            extra_data  = {
                "package_name":     pkg_name,
                "package_manager":  pkg_mgr,
                "malicious_version": pkg_ver,
                "machines_affected": targets if success else 0,
                "backdoor_type":    "reverse shell on import" if success else None,
                "update_mechanism": "auto-update pipeline",
            },
        )
