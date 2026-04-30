"""
Seed script — populates the database with default data:
- Default detection rules (Sigma)
- A demo user for testing

Run with: python -m db.seed
"""

from __future__ import annotations

import asyncio
from db.engine import init_db, get_session
from db.crud import create_user, get_user_by_username, create_detection_rule


# ---------------------------------------------------------------------------
# Default Sigma rules
# ---------------------------------------------------------------------------
DEFAULT_RULES = [
    {
        "name": "Brute Force Login Attempt",
        "description": "Detects multiple failed login attempts from a single source within a short time window.",
        "severity": "high",
        "is_default": True,
        "rule_yaml": """
title: Brute Force Login Attempt
status: experimental
description: Multiple failed logins from same source IP
logsource:
    category: authentication
    product: windows
detection:
    selection:
        event_id: 4625
    condition: selection | count(source_ip) > 5
    timeframe: 5m
level: high
tags:
    - attack.credential_access
    - attack.t1110
""",
    },
    {
        "name": "Suspicious PowerShell Execution",
        "description": "Detects encoded or obfuscated PowerShell commands commonly used in attacks.",
        "severity": "high",
        "is_default": True,
        "rule_yaml": """
title: Suspicious PowerShell Execution
status: experimental
description: Encoded or hidden PowerShell execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name: powershell.exe
        message|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-WindowStyle Hidden'
            - 'bypass'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
""",
    },
    {
        "name": "Lateral Movement via PsExec",
        "description": "Detects PsExec-style remote execution commonly used for lateral movement.",
        "severity": "critical",
        "is_default": True,
        "rule_yaml": """
title: Lateral Movement via PsExec
status: experimental
description: PsExec or similar remote execution tool detected
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name|contains:
            - 'psexec'
            - 'PSEXESVC'
    condition: selection
level: critical
tags:
    - attack.lateral_movement
    - attack.t1570
""",
    },
    {
        "name": "Data Exfiltration — Large Outbound Transfer",
        "description": "Detects unusually large outbound data transfers that may indicate exfiltration.",
        "severity": "high",
        "is_default": True,
        "rule_yaml": """
title: Large Outbound Data Transfer
status: experimental
description: Outbound transfer exceeding threshold
logsource:
    category: network_flow
detection:
    selection:
        direction: outbound
        bytes_out|gt: 50000000
    condition: selection
level: high
tags:
    - attack.exfiltration
    - attack.t1048
""",
    },
    {
        "name": "Ransomware File Encryption Pattern",
        "description": "Detects rapid file modification across multiple directories, typical of ransomware.",
        "severity": "critical",
        "is_default": True,
        "rule_yaml": """
title: Ransomware File Encryption Pattern
status: experimental
description: Mass file modifications in short timeframe
logsource:
    category: file_event
    product: windows
detection:
    selection:
        event_type: modify
        file_extension|contains:
            - '.encrypted'
            - '.locked'
            - '.crypted'
    condition: selection | count() > 20
    timeframe: 1m
level: critical
tags:
    - attack.impact
    - attack.t1486
""",
    },
    {
        "name": "C2 Beacon — Periodic Outbound Connection",
        "description": "Detects regular periodic connections to external IPs, suggesting command-and-control beaconing.",
        "severity": "medium",
        "is_default": True,
        "rule_yaml": """
title: C2 Beacon Detection
status: experimental
description: Periodic outbound connections with regular intervals
logsource:
    category: network_flow
detection:
    selection:
        direction: outbound
        destination_port:
            - 443
            - 8443
            - 8080
    condition: selection | count(destination_ip) > 10
    timeframe: 10m
level: medium
tags:
    - attack.command_and_control
    - attack.t1071
""",
    },
]


# ---------------------------------------------------------------------------
# Seed function
# ---------------------------------------------------------------------------
async def seed_database() -> None:
    """Populate database with default data."""

    # Ensure tables exist
    await init_db()

    async with get_session() as db:
        # Create demo user
        demo_user = await get_user_by_username(db, "demo")
        if demo_user is None:
            demo_user = await create_user(db, username="demo", display_name="Demo Analyst")
            print(f"[SEED] Created demo user: {demo_user.username} (id: {demo_user.id})")
        else:
            print(f"[SEED] Demo user already exists: {demo_user.username}")

        # Create default detection rules
        for rule_data in DEFAULT_RULES:
            rule = await create_detection_rule(db, **rule_data)
            print(f"[SEED] Created rule: {rule.name}")

    print(f"\n[SEED] Done — {len(DEFAULT_RULES)} default rules loaded.")


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    asyncio.run(seed_database())
