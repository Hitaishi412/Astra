"""
Generate a sample session with mock data for demo / testing.
Creates a user, session, some attack events, logs, and alerts.

Run with: python scripts/generate_sample_session.py
"""

import asyncio
import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.engine import init_db, get_session
from db import crud


async def generate():
    await init_db()

    async with get_session() as db:
        # Create user
        user = await crud.get_or_create_user(db, "demo")
        print(f"[SAMPLE] User: {user.username} ({user.id})")

        # Create session
        session = await crud.create_session(
            db,
            user_id=user.id,
            scenario_id="ransomware",
            role="full_spectrum",
            difficulty="medium",
        )
        await crud.update_session_status(db, session.id, "running")
        print(f"[SAMPLE] Session: {session.id}")

        # Create attack events
        attack_steps = [
            {
                "session_id": session.id,
                "phase": "delivery",
                "step_number": 1,
                "technique_id": "T1566.001",
                "technique_name": "Phishing: Spearphishing Attachment",
                "tactic": "initial_access",
                "description": "Sent spearphishing email with macro-enabled Word document to finance team.",
                "source_host": "external",
                "target_host": "WORKSTATION-PC07",
            },
            {
                "session_id": session.id,
                "phase": "exploitation",
                "step_number": 2,
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactic": "execution",
                "description": "Macro executed encoded PowerShell command to download second-stage payload.",
                "source_host": "WORKSTATION-PC07",
                "target_host": "WORKSTATION-PC07",
            },
            {
                "session_id": session.id,
                "phase": "installation",
                "step_number": 3,
                "technique_id": "T1547.001",
                "technique_name": "Registry Run Keys / Startup Folder",
                "tactic": "persistence",
                "description": "Added malicious DLL to HKCU Run key for persistence.",
                "source_host": "WORKSTATION-PC07",
                "target_host": "WORKSTATION-PC07",
            },
            {
                "session_id": session.id,
                "phase": "actions_on_objectives",
                "step_number": 4,
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "tactic": "impact",
                "description": "Encrypted files across shared drives using AES-256. Dropped ransom note.",
                "source_host": "WORKSTATION-PC07",
                "target_host": "FILE-SERVER-01",
            },
        ]

        for step in attack_steps:
            event = await crud.create_attack_event(db, **step)
            print(f"[SAMPLE] Attack step {step['step_number']}: {step['technique_name']}")

        # Create some alerts
        alerts = [
            {
                "session_id": session.id,
                "detection_type": "sigma",
                "title": "Suspicious PowerShell Execution Detected",
                "description": "Encoded PowerShell command executed on WORKSTATION-PC07",
                "severity": "high",
                "technique_id": "T1059.001",
                "tactic": "execution",
                "hostname": "WORKSTATION-PC07",
                "username": "jsmith",
                "is_true_positive": True,
            },
            {
                "session_id": session.id,
                "detection_type": "anomaly",
                "title": "Unusual File Modification Rate",
                "description": "FILE-SERVER-01 experienced 2,847 file modifications in 60 seconds",
                "severity": "critical",
                "technique_id": "T1486",
                "tactic": "impact",
                "hostname": "FILE-SERVER-01",
                "is_true_positive": True,
            },
        ]

        for alert_data in alerts:
            alert = await crud.create_alert(db, **alert_data)
            print(f"[SAMPLE] Alert: {alert_data['title']}")

    print("\n[SAMPLE] Done. Sample session created successfully.")


if __name__ == "__main__":
    asyncio.run(generate())
