"""
core/attack_engine/techniques/persistence.py
─────────────────────────────────────────────
MITRE ATT&CK Persistence techniques.
  - T1547.001  Boot/Logon Autostart: Registry Run Keys
  - T1053.005  Scheduled Task/Job: Scheduled Task
  - T1543.003  Create or Modify System Process: Windows Service
  - T1136.001  Create Account: Local Account
"""

from __future__ import annotations
import random
from typing import Any
from config.constants import KillChainPhase, Severity
from core.attack_engine.techniques.base import BaseTechnique, AttackStep


class RegistryRunKey(BaseTechnique):
    TECHNIQUE_ID   = "T1547.001"
    TECHNIQUE_NAME = "Boot/Logon Autostart Execution: Registry Run Keys"
    TACTIC         = "persistence"
    PHASE          = KillChainPhase.INSTALLATION
    BASE_SEVERITY  = Severity.HIGH

    KEYS = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    NAMES = ["WindowsUpdate", "SystemCheck", "NetManager", "SvcHost32", "AdobeUpdate"]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host    = context.get("initial_access_host", self._fake_hostname())
        key     = random.choice(self.KEYS)
        name    = random.choice(self.NAMES)
        payload = f"C:\\Users\\Public\\{name}.exe"
        success = self._did_succeed()

        if success:
            context["persistence_mechanism"] = f"registry:{name}"

        return self._make_step(
            description=f"Registry run key added on {host}: [{name}] → {payload}",
            source_host=host, target_host=host, success=success,
            extra_data={"registry_key": key, "value_name": name,
                        "payload_path": payload, "survives_reboot": True},
        )


class ScheduledTask(BaseTechnique):
    TECHNIQUE_ID   = "T1053.005"
    TECHNIQUE_NAME = "Scheduled Task/Job: Scheduled Task"
    TACTIC         = "persistence"
    PHASE          = KillChainPhase.INSTALLATION
    BASE_SEVERITY  = Severity.HIGH

    TASK_NAMES = ["WindowsDefenderUpdate", "MicrosoftEdgeUpdate",
                  "AdobeFlashUpdate", "JavaAutoUpdate", "SyncManager"]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host      = context.get("initial_access_host", self._fake_hostname())
        task_name = random.choice(self.TASK_NAMES)
        trigger   = random.choice(["At system startup", "Every 6 hours", "At logon"])
        success   = self._did_succeed()

        if success:
            context["persistence_mechanism"] = f"scheduled_task:{task_name}"

        return self._make_step(
            description=f"Scheduled task '{task_name}' created on {host} ({trigger})",
            source_host=host, target_host=host, success=success,
            extra_data={
                "task_name": task_name, "trigger": trigger,
                "command": f"powershell -WindowStyle Hidden -File C:\\Temp\\{task_name}.ps1",
                "run_as": "SYSTEM",
            },
        )


class CreateLocalAccount(BaseTechnique):
    TECHNIQUE_ID   = "T1136.001"
    TECHNIQUE_NAME = "Create Account: Local Account"
    TACTIC         = "persistence"
    PHASE          = KillChainPhase.INSTALLATION
    BASE_SEVERITY  = Severity.CRITICAL

    BACKDOOR_ACCOUNTS = ["svc_backup", "helpdesk01", "admin_temp",
                          "support_acc", "maint_user"]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host     = context.get("initial_access_host", self._fake_hostname())
        acct     = random.choice(self.BACKDOOR_ACCOUNTS)
        success  = self._did_succeed()

        if success:
            context["backdoor_account"] = acct

        return self._make_step(
            description=f"Backdoor local account '{acct}' created on {host} with admin privileges",
            source_host=host, target_host=host, success=success,
            severity=Severity.CRITICAL.value,
            extra_data={
                "account_name": acct,
                "password": "[REDACTED]",
                "groups": ["Administrators", "Remote Desktop Users"],
                "added_to_domain": False,
            },
        )
