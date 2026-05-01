"""
core/log_engine/generator.py
─────────────────────────────
Ingests an AttackStep from Block 2 and produces a list of LogEntry objects
that match the Block 4 contract defined in core/log_engine/schemas.py.

Architecture
────────────
                        ┌─────────────────────┐
   AttackStep  ──────►  │   LogGenerator       │  ──────►  list[LogEntry]
                        │                     │
                        │ 1. technique_id      │
                        │    → load YAML tmpl  │
                        │ 2. render variables  │
                        │ 3. build LogEntry    │
                        │ 4. repeat per hint   │
                        └─────────────────────┘

Key design decisions
────────────────────
  - Templates live in YAML (data/log_templates/). The generator never hard-codes
    log messages — that's the YAML's job.
  - Every generated log has is_malicious=True and attack_event_id=step.id so
    Block 4 can compute ground-truth TP/FP rates.
  - log_count_hint from the AttackStep controls how many logs to emit per step.
    Beginners generate many logs (noisy); experts generate few (evasive).
  - If no template exists for a technique_id, a generic fallback log is emitted
    so no AttackStep is ever silently dropped.
  - Timestamps are jittered ±30 seconds around the step's timestamp so the log
    stream looks organic rather than exactly simultaneous.
"""

from __future__ import annotations

import copy
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from core.attack_engine.techniques.base import AttackStep
from core.log_engine.schemas import LogEntry


# ─── Template loading ─────────────────────────────────────────────────────────

_TEMPLATE_DIR = Path(__file__).parent.parent.parent / "data" / "log_templates"

# {technique_id: [template_dict, ...]}  — populated once on first use
_TECHNIQUE_MAP: dict[str, list[dict]] = {}
_TEMPLATES_LOADED = False


def _load_templates() -> None:
    """
    Read all YAML template files and build the technique → templates index.
    Called once on first generate() call (lazy load).
    """
    global _TEMPLATES_LOADED
    if _TEMPLATES_LOADED:
        return

    for fname in ("windows_attack.yml", "linux_attack.yml"):
        fpath = _TEMPLATE_DIR / fname
        if not fpath.exists():
            continue
        with open(fpath, encoding="utf-8") as fh:
            entries = yaml.safe_load(fh) or []
        for entry in entries:
            tid = entry.get("technique_id", "")
            if tid:
                _TECHNIQUE_MAP.setdefault(tid, []).extend(entry.get("logs", []))

    _TEMPLATES_LOADED = True


# ─── Variable resolution ──────────────────────────────────────────────────────

_COMMON_PROCESSES = [
    "explorer.exe", "svchost.exe", "taskhostw.exe",
    "SearchIndexer.exe", "RuntimeBroker.exe",
]

_COMMON_SERVICES = [
    "wuauserv", "BITS", "Spooler", "LanmanWorkstation", "Netlogon",
]


def _build_vars(step: AttackStep) -> dict[str, str]:
    """
    Build the variable substitution dict from an AttackStep.
    Every {placeholder} in the YAML templates resolves from here.
    """
    ed = step.extra_data or {}
    username = (
        ed.get("username")
        or ed.get("target_user")
        or ed.get("account_name")
        or step.source_host
        or "jsmith"
    )
    source_ip = _host_to_ip(step.source_host) or _rand_external_ip()
    target_ip = _host_to_ip(step.target_host) or _rand_internal_ip()

    return {
        "source_host":   str(step.source_host or "ATTACKER-HOST"),
        "target_host":   str(step.target_host or "VICTIM-HOST"),
        "username":      str(username),
        "source_ip":     source_ip,
        "target_ip":     target_ip,
        "command_line":  str(ed.get("command", ed.get("command_line", step.description[:80]))),
        "process_name":  str(ed.get("tool", random.choice(_COMMON_PROCESSES))),
        "parent_process": random.choice(["explorer.exe", "cmd.exe", "WINWORD.EXE", "wscript.exe"]),
        "service":       str(ed.get("service", ed.get("spn", random.choice(_COMMON_SERVICES)))),
        "task_name":     str(ed.get("task_name", "WindowsUpdate")),
        "registry_key":  str(ed.get("registry_key", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")),
        "file_path":     str(ed.get("file_targeted", ed.get("files", ["C:\\Windows\\Temp\\update.exe"])[0] if isinstance(ed.get("files"), list) else "C:\\Windows\\Temp\\update.exe")),
        "port":          str(ed.get("shell_port", ed.get("dst_port", ed.get("port", random.choice([443, 80, 4444, 3389, 445]))))),
        "payload":       str(ed.get("attachment", ed.get("package_name", step.technique_name))),
        "hash":          str(ed.get("ntlm_hash", "aad3b435..."))[:20] + "...",
        "ticket_type":   str(ed.get("ticket_type", "TGT")),
        "bytes":         str(ed.get("bytes_this_chunk", ed.get("exfil_bytes", random.randint(50000, 5000000)))),
        "c2_domain":     str(ed.get("c2_domain", ed.get("c2_server", _rand_external_ip()))),
        "family":        str(ed.get("ransomware_family", "LockBit")),
        "ext":           str(ed.get("extension", ".locked")),
        "count":         str(ed.get("files_encrypted", random.randint(100, 50000))),
        "package":       str(ed.get("package_name", "unknown-pkg")),
        "cve":           str(ed.get("cve_id", ed.get("method", "CVE-2021-44228"))),
        "pid":           str(random.randint(1000, 65535)),
        "src_port":      str(random.randint(40000, 65535)),
        "dst_port":      str(random.randint(1, 1024)),
        "hex":           "".join(random.choices("0123456789abcdef", k=6)),
        "ts":            datetime.now(timezone.utc).strftime("%s"),
    }


def _resolve(value: Any, vars_: dict[str, str]) -> Any:
    """Recursively substitute {placeholders} in strings and nested dicts/lists."""
    if isinstance(value, str):
        try:
            return value.format_map(vars_)
        except (KeyError, ValueError):
            return value
    if isinstance(value, dict):
        return {k: _resolve(v, vars_) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(item, vars_) for item in value]
    return value


# ─── IP helpers ───────────────────────────────────────────────────────────────

def _host_to_ip(host: Optional[str]) -> Optional[str]:
    """If host looks like an IP, return it. Otherwise return None."""
    if host and all(c.isdigit() or c == "." for c in host) and host.count(".") == 3:
        return host
    return None


def _rand_internal_ip() -> str:
    return f"10.0.{random.randint(1, 10)}.{random.randint(2, 254)}"


def _rand_external_ip() -> str:
    return f"{random.randint(50, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(2, 254)}"


# ─── Timestamp jitter ─────────────────────────────────────────────────────────

def _jitter_ts(base: datetime, max_seconds: int = 30) -> datetime:
    """Return a timestamp within ±max_seconds of base."""
    offset = random.randint(-max_seconds, max_seconds)
    return base + timedelta(seconds=offset)


# ─── Fallback log ─────────────────────────────────────────────────────────────

def _fallback_log(step: AttackStep, session_id: str, vars_: dict) -> LogEntry:
    """
    Emit a generic EDR log when no YAML template exists for a technique.
    This guarantees every AttackStep produces at least one log.
    """
    return LogEntry(
        session_id      = session_id,
        attack_event_id = step.id,
        source          = "endpoint_edr",
        event_id        = 1,
        severity        = step.severity if step.severity in ("info", "low", "medium", "high", "critical") else "medium",
        category        = "process_creation",
        message         = (
            f"[{step.technique_id}] {step.technique_name}: {step.description[:200]}"
        ),
        hostname        = vars_.get("target_host"),
        source_ip       = vars_.get("source_ip"),
        destination_ip  = vars_.get("target_ip"),
        username        = vars_.get("username"),
        process_name    = vars_.get("process_name"),
        command_line    = vars_.get("command_line"),
        is_malicious    = True,
        timestamp       = _jitter_ts(step.timestamp),
        raw_data        = {
            "technique_id":   step.technique_id,
            "technique_name": step.technique_name,
            "tactic":         step.tactic,
            "phase":          step.phase,
            "fallback":       True,
        },
    )


# ─── Template → LogEntry ──────────────────────────────────────────────────────

def _template_to_log_entry(
    tmpl: dict,
    vars_: dict[str, str],
    step: AttackStep,
    session_id: str,
) -> LogEntry:
    """
    Expand one YAML template dict into a LogEntry, resolving all {variables}.
    """
    resolved = _resolve(copy.deepcopy(tmpl), vars_)
    fields   = resolved.get("fields", {})
    raw_data = fields.pop("raw_data", {}) if isinstance(fields.get("raw_data"), dict) else {}

    # Resolve port fields to int safely
    def _safe_int(v: Any) -> Optional[int]:
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    sev = resolved.get("severity", "info")
    valid_severities = {"info", "low", "medium", "high", "critical"}
    if sev not in valid_severities:
        sev = "info"

    return LogEntry(
        session_id       = session_id,
        attack_event_id  = step.id,
        source           = resolved.get("source", "endpoint_edr"),
        event_id         = resolved.get("event_id"),
        severity         = sev,
        category         = resolved.get("category"),
        message          = resolved.get("message", ""),
        hostname         = fields.get("hostname", vars_.get("target_host")),
        source_ip        = fields.get("source_ip", vars_.get("source_ip")),
        destination_ip   = fields.get("destination_ip", vars_.get("target_ip")),
        source_port      = _safe_int(fields.get("source_port")),
        destination_port = _safe_int(fields.get("destination_port")),
        username         = fields.get("username", vars_.get("username")),
        process_name     = fields.get("process_name", vars_.get("process_name")),
        process_id       = _safe_int(fields.get("process_id")),
        parent_process   = fields.get("parent_process", vars_.get("parent_process")),
        file_path        = fields.get("file_path", vars_.get("file_path")),
        command_line     = fields.get("command_line", vars_.get("command_line")),
        is_malicious     = True,
        raw_data         = {**raw_data, "technique_id": step.technique_id},
        timestamp        = _jitter_ts(step.timestamp),
    )


# ─── Public interface ─────────────────────────────────────────────────────────

class LogGenerator:
    """
    Converts AttackStep objects into lists of LogEntry objects.

    Usage (sync):
        gen = LogGenerator()
        logs = gen.generate(step, session_id="abc-123")
        for log in logs:
            await crud.create_log_entry(db, **log.to_db_dict())

    Usage (streaming, one step at a time):
        async for step in orchestrator.run_scenario_async("ransomware"):
            logs = gen.generate(step, session_id=session_id)
            await crud.bulk_create_log_entries(db, [l.to_db_dict() for l in logs])
    """

    def __init__(self, template_dir: Optional[Path] = None):
        global _TEMPLATE_DIR
        if template_dir:
            _TEMPLATE_DIR = Path(template_dir)
        _load_templates()

    def generate(
        self,
        step: AttackStep,
        session_id: str,
    ) -> list[LogEntry]:
        """
        Main entry point.

        Takes one AttackStep and returns log_count_hint LogEntry objects.

        For each log requested:
          1. Look up YAML templates for step.technique_id
          2. If multiple templates exist, cycle through them (variety)
          3. Resolve all {variables} from step.extra_data
          4. Construct and validate a LogEntry
          5. Return the full list

        Returns at least one log (fallback) even if no template exists.
        """
        tid      = step.technique_id
        templates = _TECHNIQUE_MAP.get(tid, [])
        vars_    = _build_vars(step)
        count    = max(1, step.log_count_hint)
        logs: list[LogEntry] = []

        if not templates:
            # No template — emit fallback + extras as generic process creation
            logs.append(_fallback_log(step, session_id, vars_))
            for _ in range(count - 1):
                logs.append(_fallback_log(step, session_id, vars_))
            return logs

        # Cycle through available templates to produce `count` logs
        for i in range(count):
            tmpl = templates[i % len(templates)]
            try:
                log = _template_to_log_entry(tmpl, vars_, step, session_id)
                logs.append(log)
            except Exception as exc:
                # Never fail silently — emit a fallback instead
                fb = _fallback_log(step, session_id, vars_)
                fb.raw_data["template_error"] = str(exc)
                logs.append(fb)

        return logs

    def generate_from_scenario(
        self,
        steps: list[AttackStep],
        session_id: str,
    ) -> list[LogEntry]:
        """
        Convenience: generate logs for an entire list of steps in one call.
        Returns all logs interleaved in step order.
        """
        all_logs: list[LogEntry] = []
        for step in steps:
            all_logs.extend(self.generate(step, session_id))
        return all_logs

    @staticmethod
    def supported_techniques() -> list[str]:
        """Return technique IDs that have explicit YAML templates."""
        _load_templates()
        return sorted(_TECHNIQUE_MAP.keys())
