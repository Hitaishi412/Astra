"""
streaming/injector.py
──────────────────────
Test helper — generates fake LogEntry and Alert messages and publishes them
to the streaming backend. Used to verify the streaming pipeline end-to-end
*before* Block 3 (Log Engine) is built.

This is NOT used in production. It exists only so:
  - You can manually test WebSocket streaming with `python -m streaming.injector`
  - The test suite has a deterministic source of stream traffic

Usage from terminal:
    python -m streaming.injector --session-id abc --rate 10

Usage from tests:
    from streaming.injector import inject_burst, inject_stream
    await inject_burst(session_id="abc", count=20)
"""

from __future__ import annotations

import argparse
import asyncio
import random
import uuid
from datetime import datetime, timezone
from typing import Optional

from streaming.publisher import (
    publish_alert,
    publish_attack_status,
    publish_log,
    publish_score,
)


# ─── Fake content ───────────────────────────────────────────────────────────
_FAKE_HOSTS = ["WORKSTATION-01", "DC-01", "FILE-SERVER", "WEB-FRONT", "DB-PROD"]
_FAKE_USERS = ["jsmith", "amartinez", "lnguyen", "kpatel", "rlee"]
_FAKE_PROCESSES = ["explorer.exe", "powershell.exe", "cmd.exe", "chrome.exe", "svchost.exe"]


def _fake_ip() -> str:
    return f"10.0.{random.randint(1, 10)}.{random.randint(2, 254)}"


def _fake_log(session_id: str, malicious: bool = False) -> dict:
    """Build a fake LogEntry-shaped dict."""
    if malicious:
        process_name = "powershell.exe"
        command_line = "powershell -enc JABzAD0ATgBl..."
        message = "Encoded PowerShell execution detected"
        category = "process_creation"
    else:
        process_name = random.choice(_FAKE_PROCESSES)
        command_line = f"{process_name}"
        message = f"{process_name} started normally"
        category = "process_creation"

    return {
        "id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "windows_event",
        "event_id": 4688,
        "severity": "high" if malicious else "info",
        "category": category,
        "message": message,
        "hostname": random.choice(_FAKE_HOSTS),
        "source_ip": _fake_ip(),
        "username": random.choice(_FAKE_USERS),
        "process_name": process_name,
        "command_line": command_line,
        "is_malicious": malicious,
        "raw_data": {},
    }


def _fake_alert(session_id: str) -> dict:
    """Build a fake Alert-shaped dict."""
    return {
        "id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detection_type": "sigma",
        "rule_id": "test_rule",
        "rule_name": "Suspicious PowerShell Execution",
        "title": "Suspicious PowerShell Execution Detected",
        "description": "Encoded command execution observed",
        "severity": random.choice(["medium", "high", "critical"]),
        "technique_id": "T1059.001",
        "tactic": "execution",
        "hostname": random.choice(_FAKE_HOSTS),
        "source_ip": _fake_ip(),
        "username": random.choice(_FAKE_USERS),
        "evidence": {"log_count": random.randint(1, 5)},
        "triage_status": "new",
        "is_true_positive": True,
    }


# ─── Single bursts ──────────────────────────────────────────────────────────
async def inject_burst(
    session_id: str,
    count: int = 10,
    malicious_ratio: float = 0.2,
) -> int:
    """
    Publish `count` fake logs to the session's logs channel.
    Returns total subscribers reached (0 if no one is listening).
    """
    total = 0
    for _ in range(count):
        log = _fake_log(
            session_id,
            malicious=random.random() < malicious_ratio,
        )
        total += await publish_log(session_id, log)
    return total


async def inject_alert(session_id: str) -> int:
    """Publish one fake alert."""
    return await publish_alert(session_id, _fake_alert(session_id))


async def inject_attack_status(session_id: str) -> int:
    """Publish a fake kill chain status update."""
    phases = [
        "reconnaissance", "delivery", "exploitation",
        "installation", "command_and_control", "actions_on_objectives",
    ]
    progress = random.randint(0, 100)
    return await publish_attack_status(session_id, {
        "state": "running",
        "current_phase": random.choice(phases),
        "progress_pct": progress,
        "phases_completed": phases[:int(progress / 16)],
        "total_steps": progress // 5,
    })


# ─── Continuous stream ──────────────────────────────────────────────────────
async def inject_stream(
    session_id: str,
    duration_seconds: int = 60,
    rate_per_second: float = 5.0,
    malicious_ratio: float = 0.15,
) -> dict:
    """
    Continuously publish fake events for a duration.
    Useful for manually testing the dashboard UI.
    """
    end_time = asyncio.get_event_loop().time() + duration_seconds
    interval = 1.0 / max(rate_per_second, 0.1)

    counts = {"logs": 0, "alerts": 0, "attack_status": 0}

    while asyncio.get_event_loop().time() < end_time:
        # Mostly logs
        await inject_burst(session_id, count=1, malicious_ratio=malicious_ratio)
        counts["logs"] += 1

        # Occasional alert (~10% of the time)
        if random.random() < 0.10:
            await inject_alert(session_id)
            counts["alerts"] += 1

        # Periodic attack status update (~5%)
        if random.random() < 0.05:
            await inject_attack_status(session_id)
            counts["attack_status"] += 1

        await asyncio.sleep(interval)

    return counts


# ─── CLI entry ──────────────────────────────────────────────────────────────
async def _cli_main(args: argparse.Namespace) -> None:
    print(f"[INJECTOR] Streaming fake events to session={args.session_id} "
          f"for {args.duration}s at {args.rate}/s...")
    counts = await inject_stream(
        session_id=args.session_id,
        duration_seconds=args.duration,
        rate_per_second=args.rate,
    )
    print(f"[INJECTOR] Done: {counts}")


def main():
    parser = argparse.ArgumentParser(description="ASTRA streaming test injector")
    parser.add_argument("--session-id", default="demo_session", help="Session ID")
    parser.add_argument("--duration", type=int, default=30, help="Seconds to run")
    parser.add_argument("--rate", type=float, default=5.0, help="Events per second")
    args = parser.parse_args()
    asyncio.run(_cli_main(args))


if __name__ == "__main__":
    main()
