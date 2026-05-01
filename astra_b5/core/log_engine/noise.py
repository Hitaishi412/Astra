"""
core/log_engine/noise.py
─────────────────────────
Generates realistic benign background log traffic for a training session.

Why noise matters
─────────────────
A real SOC sees thousands of benign events per hour and must distinguish
those from the handful of malicious ones. Without noise, every log in the
training session is obviously malicious — making detection trivially easy.
Noise forces trainees to write precise Sigma rules that don't produce
thousands of false positives.

Design
──────
  - Rate: 10–20 benign logs per minute (randomised each call)
  - Sources: Windows events, Linux syslog, network flows — weighted
  - All noise logs have is_malicious=False and attack_event_id=None
  - Timestamps cluster around the requested minute, jittered ±30s
  - NoiseGenerator can run as a background task (generate_for_duration)
    or be called per-step to interleave noise with attack logs

Noise templates are loaded from data/log_templates/noise.yml.
"""

from __future__ import annotations

import asyncio
import copy
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import yaml

from core.log_engine.schemas import LogEntry


# ─── Template loading ─────────────────────────────────────────────────────────

_TEMPLATE_DIR  = Path(__file__).parent.parent.parent / "data" / "log_templates"
_NOISE_TEMPLATES: dict[str, list[dict]] = {}   # "windows" / "linux" / "network"
_NOISE_LOADED  = False


def _load_noise_templates() -> None:
    global _NOISE_LOADED
    if _NOISE_LOADED:
        return
    fpath = _TEMPLATE_DIR / "noise.yml"
    if not fpath.exists():
        _NOISE_LOADED = True
        return
    with open(fpath, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    for section, entries in data.items():
        _NOISE_TEMPLATES[section] = entries or []
    _NOISE_LOADED = True


# ─── Fake data pools ──────────────────────────────────────────────────────────

_USERNAMES = [
    "jsmith", "amartinez", "bwilson", "lnguyen", "mgarcia",
    "tcook", "rlee", "sjohnson", "kpatel", "dthompson",
    "hbrown", "ewatson", "cjones", "mdavis", "owhite",
]

_HOSTNAMES = [
    "DESKTOP-WK001", "DESKTOP-WK002", "DESKTOP-WK003",
    "LAPTOP-DEV01", "LAPTOP-DEV02",
    "SRV-DC01", "SRV-FILE01", "SRV-WEB01",
    "WORKSTATION-HR1", "WORKSTATION-ACC1",
]

_INTERNAL_IPS  = [f"10.0.{s}.{h}" for s in range(1, 5) for h in range(2, 20)]
_EXTERNAL_IPS  = ["8.8.8.8", "1.1.1.1", "20.112.52.29", "13.107.4.52",
                   "52.96.0.0", "104.21.4.1", "151.101.1.44"]

_PROCESSES     = [
    "explorer.exe", "chrome.exe", "msedge.exe", "svchost.exe",
    "taskhostw.exe", "SearchIndexer.exe", "OneDrive.exe",
    "Teams.exe", "Outlook.exe", "notepad.exe",
]

_SERVICES      = [
    "wuauserv", "BITS", "Spooler", "WinRM",
    "LanmanWorkstation", "Netlogon", "NlaSvc",
]


def _noise_vars() -> dict[str, str]:
    src_ip = random.choice(_INTERNAL_IPS)
    dst_ip = random.choice(_INTERNAL_IPS + _EXTERNAL_IPS)
    return {
        "username":       random.choice(_USERNAMES),
        "hostname":       random.choice(_HOSTNAMES),
        "source_ip":      src_ip,
        "destination_ip": dst_ip,
        "process_name":   random.choice(_PROCESSES),
        "service":        random.choice(_SERVICES),
        "port":           str(random.choice([80, 443, 22, 53, 3389, 8080])),
        "src_port":       str(random.randint(40000, 65535)),
        "dst_port":       str(random.randint(1, 1024)),
        "bytes":          str(random.randint(512, 65536)),
        "pid":            str(random.randint(1000, 65535)),
    }


def _resolve(value, vars_: dict) -> any:
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


def _jitter(base: datetime, max_seconds: int = 30) -> datetime:
    return base + timedelta(seconds=random.randint(-max_seconds, max_seconds))


def _safe_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ─── Template → LogEntry ──────────────────────────────────────────────────────

def _noise_template_to_log(
    tmpl_entry: dict,
    vars_: dict[str, str],
    session_id: str,
    base_time: datetime,
) -> LogEntry:
    tmpl     = copy.deepcopy(tmpl_entry["template"])
    resolved = _resolve(tmpl, vars_)
    fields   = resolved.get("fields", {})
    raw_data = fields.pop("raw_data", {}) if isinstance(fields.get("raw_data"), dict) else {}

    sev = resolved.get("severity", "info")
    if sev not in {"info", "low", "medium", "high", "critical"}:
        sev = "info"

    return LogEntry(
        session_id       = session_id,
        attack_event_id  = None,           # benign — no attack event
        source           = resolved.get("source", "windows_event"),
        event_id         = resolved.get("event_id"),
        severity         = sev,
        category         = resolved.get("category"),
        message          = resolved.get("message", ""),
        hostname         = fields.get("hostname", vars_["hostname"]),
        source_ip        = fields.get("source_ip", vars_["source_ip"]),
        destination_ip   = fields.get("destination_ip", vars_["destination_ip"]),
        source_port      = _safe_int(fields.get("source_port")),
        destination_port = _safe_int(fields.get("destination_port")),
        username         = fields.get("username", vars_["username"]),
        process_name     = fields.get("process_name", vars_["process_name"]),
        process_id       = _safe_int(fields.get("process_id")),
        parent_process   = fields.get("parent_process"),
        file_path        = fields.get("file_path"),
        command_line     = fields.get("command_line"),
        is_malicious     = False,          # ← ground truth: benign
        raw_data         = raw_data,
        timestamp        = _jitter(base_time),
    )


# ─── Weighted sampler ─────────────────────────────────────────────────────────

def _weighted_choice(entries: list[dict]) -> dict:
    weights = [e.get("weight", 1) for e in entries]
    return random.choices(entries, weights=weights, k=1)[0]


def _pick_section() -> str:
    """Decide which log source family to generate noise from."""
    return random.choices(
        ["windows", "linux", "network"],
        weights=[50, 30, 20],
        k=1,
    )[0]


# ─── Public interface ─────────────────────────────────────────────────────────

class NoiseGenerator:
    """
    Produces bursts of benign log entries to simulate background traffic.

    Usage (per-step interleaving):
        noise_gen = NoiseGenerator()
        attack_logs = log_gen.generate(step, session_id)
        noise_logs  = noise_gen.burst(session_id, count=step.noise_count_hint)
        all_logs    = attack_logs + noise_logs   # mix before persisting

    Usage (continuous background task):
        async for batch in noise_gen.stream(session_id, rate_per_min=15):
            await crud.bulk_create_log_entries(db, [l.to_db_dict() for l in batch])

    Usage (fixed duration for test seeding):
        logs = noise_gen.generate_for_duration(session_id, duration_minutes=5)
    """

    # Rate window: emit one burst of noise every BATCH_INTERVAL seconds
    BATCH_INTERVAL = 60    # 1 minute

    def __init__(self, template_dir: Optional[Path] = None):
        global _TEMPLATE_DIR
        if template_dir:
            _TEMPLATE_DIR = Path(template_dir)
        _load_noise_templates()

    # ── Single burst ──────────────────────────────────────────────────────────

    def burst(
        self,
        session_id: str,
        count: Optional[int] = None,
        base_time: Optional[datetime] = None,
    ) -> list[LogEntry]:
        """
        Generate one burst of benign noise.

        Args:
            session_id : session to attach logs to
            count      : number of logs (default: random 10–20)
            base_time  : anchor timestamp (default: now)

        Returns:
            List of LogEntry objects with is_malicious=False
        """
        n    = count if count is not None else random.randint(10, 20)
        now  = base_time or datetime.now(timezone.utc)
        logs = []

        for _ in range(n):
            section = _pick_section()
            entries = _NOISE_TEMPLATES.get(section, [])
            if not entries:
                continue

            entry  = _weighted_choice(entries)
            vars_  = _noise_vars()
            try:
                log = _noise_template_to_log(entry, vars_, session_id, now)
                logs.append(log)
            except Exception:
                # Never propagate noise-generation errors
                continue

        return logs

    # ── Async streaming (background task) ─────────────────────────────────────

    async def stream(
        self,
        session_id: str,
        rate_per_min: int = 15,
        stop_event: Optional[asyncio.Event] = None,
    ):
        """
        Async generator that yields one burst of noise every minute.

        Args:
            session_id   : session to attach logs to
            rate_per_min : target noise logs per minute (10–20 recommended)
            stop_event   : set this to stop the stream gracefully

        Yields:
            list[LogEntry] — one burst per minute

        Usage:
            stop = asyncio.Event()
            async for batch in noise_gen.stream(session_id, stop_event=stop):
                await crud.bulk_create_log_entries(db, [l.to_db_dict() for l in batch])
                # Set stop.set() when session ends
        """
        while True:
            if stop_event and stop_event.is_set():
                break

            # Randomise count around the target rate (±30%)
            count = max(1, int(rate_per_min * random.uniform(0.7, 1.3)))
            batch = self.burst(session_id=session_id, count=count)
            yield batch

            # Sleep for one minute (interruptible)
            try:
                await asyncio.wait_for(
                    asyncio.shield(stop_event.wait() if stop_event else asyncio.sleep(9999)),
                    timeout=self.BATCH_INTERVAL,
                )
                break   # stop_event was set
            except asyncio.TimeoutError:
                continue   # normal — loop again after 60s

    # ── Fixed-duration generation (for seeding / testing) ─────────────────────

    def generate_for_duration(
        self,
        session_id: str,
        duration_minutes: float = 5.0,
        rate_per_min: int = 15,
        start_time: Optional[datetime] = None,
    ) -> list[LogEntry]:
        """
        Generate noise logs for a fixed duration as if they arrived in real time.

        Useful for seeding the DB with a realistic pre-session baseline
        so the anomaly detector in Block 4 has normal traffic to learn from.

        Args:
            session_id       : session to attach logs to
            duration_minutes : simulated window (default 5 minutes)
            rate_per_min     : average noise rate
            start_time       : start of the window (default: now - duration)

        Returns:
            All generated noise logs, timestamped across the window.
        """
        all_logs: list[LogEntry] = []
        base     = start_time or (
            datetime.now(timezone.utc) - timedelta(minutes=duration_minutes)
        )
        minutes  = int(duration_minutes)

        for i in range(max(1, minutes)):
            window_start = base + timedelta(minutes=i)
            count        = max(1, int(rate_per_min * random.uniform(0.7, 1.3)))
            batch        = self.burst(
                session_id = session_id,
                count      = count,
                base_time  = window_start,
            )
            all_logs.extend(batch)

        return all_logs

    # ── Interleave helper ─────────────────────────────────────────────────────

    @staticmethod
    def interleave(
        attack_logs: list[LogEntry],
        noise_logs:  list[LogEntry],
    ) -> list[LogEntry]:
        """
        Merge attack and noise logs into a single timestamp-sorted stream.
        This is what the detection engine actually sees — attack events
        mixed into background traffic.
        """
        combined = attack_logs + noise_logs
        combined.sort(key=lambda log: log.timestamp)
        return combined
