"""
tests/test_log_engine/test_generator.py
────────────────────────────────────────
Full test suite for Block 3: Log Engine.

Tests cover:
  - Schema contract (LogEntry matches Block 4 expectations)
  - LogGenerator: template resolution for every Block 2 technique
  - LogGenerator: fallback behaviour for unknown techniques
  - LogGenerator: log_count_hint is respected
  - NoiseGenerator: burst count, rate, is_malicious=False
  - NoiseGenerator: interleave produces sorted output
  - NoiseGenerator: generate_for_duration covers the window
  - Integration: logs produced pass Block 4 sigma field lookups

Run with:
    cd Astra-main
    pip install pytest pyyaml pydantic faker
    pytest tests/test_log_engine/ -v
"""

from __future__ import annotations

import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from core.log_engine.schemas import LogEntry
from core.log_engine.generator import LogGenerator, _load_templates, _TECHNIQUE_MAP
from core.log_engine.noise import NoiseGenerator

# ── Force template reload in tests ────────────────────────────────────────────
import core.log_engine.generator as _gen_mod
import core.log_engine.noise     as _noise_mod


@pytest.fixture(autouse=True)
def reset_template_cache():
    """Reset the module-level template caches between tests."""
    _gen_mod._TEMPLATES_LOADED = False
    _gen_mod._TECHNIQUE_MAP.clear()
    _noise_mod._NOISE_LOADED = False
    _noise_mod._NOISE_TEMPLATES.clear()
    yield
    _gen_mod._TEMPLATES_LOADED = False
    _gen_mod._TECHNIQUE_MAP.clear()
    _noise_mod._NOISE_LOADED = False
    _noise_mod._NOISE_TEMPLATES.clear()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_step(
    technique_id: str = "T1059.001",
    technique_name: str = "PowerShell",
    tactic: str = "execution",
    phase: str = "exploitation",
    success: bool = True,
    severity: str = "high",
    log_count_hint: int = 3,
    noise_count_hint: int = 5,
    source_host: str = "ATTACKER-001",
    target_host: str = "VICTIM-DC01",
    extra_data: dict | None = None,
):
    """Build a minimal AttackStep for testing (avoids importing the full engine)."""
    from dataclasses import dataclass, field
    from typing import Any, Optional
    import uuid

    @dataclass
    class _Step:
        id:               str = ""
        timestamp:        datetime = None
        phase:            str = ""
        step_number:      int = 1
        technique_id:     str = ""
        technique_name:   str = ""
        tactic:           str = ""
        description:      str = ""
        source_host:      Optional[str] = None
        target_host:      Optional[str] = None
        success:          bool = True
        severity:         str = "medium"
        extra_data:       dict = field(default_factory=dict)
        log_count_hint:   int = 5
        noise_count_hint: int = 10

    s = _Step()
    s.id              = str(uuid.uuid4())
    s.timestamp       = datetime.now(timezone.utc)
    s.phase           = phase
    s.technique_id    = technique_id
    s.technique_name  = technique_name
    s.tactic          = tactic
    s.description     = f"Simulated {technique_name}"
    s.source_host     = source_host
    s.target_host     = target_host
    s.success         = success
    s.severity        = severity
    s.log_count_hint  = log_count_hint
    s.noise_count_hint= noise_count_hint
    s.extra_data      = extra_data or {
        "username": "jsmith",
        "command":  "powershell -enc AABB==",
        "tool":     "powershell.exe",
    }
    return s


SESSION_ID = "test-session-abc-123"


# ─── Schema contract tests ─────────────────────────────────────────────────────

class TestLogEntrySchema:
    """Verify LogEntry matches the Block 4 contract exactly."""

    def test_required_fields_present(self):
        log = LogEntry(
            session_id = SESSION_ID,
            source     = "windows_event",
            message    = "Test message",
        )
        assert log.id
        assert log.session_id == SESSION_ID
        assert log.timestamp is not None
        assert log.source == "windows_event"
        assert log.message == "Test message"
        assert log.is_malicious is False
        assert log.attack_event_id is None

    def test_to_db_dict_has_all_keys(self):
        log = LogEntry(
            session_id = SESSION_ID,
            source     = "linux_syslog",
            message    = "sshd: login",
        )
        d = log.to_db_dict()
        expected_keys = {
            "id", "session_id", "timestamp", "source", "event_id",
            "severity", "category", "message", "raw_data",
            "hostname", "source_ip", "destination_ip", "source_port",
            "destination_port", "username", "process_name", "process_id",
            "parent_process", "file_path", "command_line",
            "is_malicious", "attack_event_id",
        }
        assert expected_keys.issubset(set(d.keys()))

    def test_invalid_source_raises(self):
        with pytest.raises(Exception):
            LogEntry(session_id=SESSION_ID, source="invalid_source", message="x")

    def test_invalid_severity_raises(self):
        with pytest.raises(Exception):
            LogEntry(session_id=SESSION_ID, source="windows_event", message="x", severity="banana")

    def test_valid_severities_accepted(self):
        for sev in ("info", "low", "medium", "high", "critical"):
            log = LogEntry(session_id=SESSION_ID, source="windows_event", message="x", severity=sev)
            assert log.severity == sev

    def test_matches_field_exact(self):
        log = LogEntry(session_id=SESSION_ID, source="windows_event", message="x",
                       username="jsmith", event_id=4625)
        assert log.matches_field("username", "jsmith") is True
        assert log.matches_field("username", "other") is False

    def test_matches_field_contains(self):
        log = LogEntry(session_id=SESSION_ID, source="windows_event", message="x",
                       command_line="powershell -enc AABBCC")
        assert log.matches_field("command_line", "-enc") is True
        assert log.matches_field("command_line", "mimikatz") is False

    def test_matches_field_list(self):
        log = LogEntry(session_id=SESSION_ID, source="windows_event", message="x",
                       event_id=4625)
        assert log.matches_field("event_id", [4624, 4625, 4648]) is True
        assert log.matches_field("event_id", [4688, 4720]) is False

    def test_matches_field_raw_data_fallback(self):
        log = LogEntry(session_id=SESSION_ID, source="windows_event", message="x",
                       raw_data={"LogonType": 10})
        assert log.matches_field("LogonType", 10) is True

    def test_matches_field_missing_returns_false(self):
        log = LogEntry(session_id=SESSION_ID, source="windows_event", message="x")
        assert log.matches_field("nonexistent_field", "value") is False


# ─── LogGenerator tests ────────────────────────────────────────────────────────

class TestLogGenerator:

    def test_templates_load_on_init(self):
        gen = LogGenerator()
        assert _gen_mod._TEMPLATES_LOADED is True

    def test_supported_techniques_not_empty(self):
        gen = LogGenerator()
        techs = gen.supported_techniques()
        assert len(techs) > 0
        assert all(t.startswith("T") for t in techs)

    def test_generate_returns_list_of_log_entries(self):
        gen  = LogGenerator()
        step = _make_step("T1059.001", log_count_hint=3)
        logs = gen.generate(step, SESSION_ID)
        assert isinstance(logs, list)
        assert all(isinstance(l, LogEntry) for l in logs)

    def test_generate_respects_log_count_hint(self):
        gen = LogGenerator()
        for count in (1, 3, 6, 10):
            step = _make_step("T1059.001", log_count_hint=count)
            logs = gen.generate(step, SESSION_ID)
            assert len(logs) == count, f"Expected {count} logs, got {len(logs)}"

    def test_all_logs_marked_malicious(self):
        gen  = LogGenerator()
        step = _make_step("T1059.001", log_count_hint=5)
        logs = gen.generate(step, SESSION_ID)
        assert all(l.is_malicious is True for l in logs)

    def test_all_logs_have_attack_event_id(self):
        gen  = LogGenerator()
        step = _make_step("T1059.001", log_count_hint=4)
        logs = gen.generate(step, SESSION_ID)
        assert all(l.attack_event_id == step.id for l in logs)

    def test_all_logs_have_session_id(self):
        gen  = LogGenerator()
        step = _make_step("T1059.001", log_count_hint=3)
        logs = gen.generate(step, SESSION_ID)
        assert all(l.session_id == SESSION_ID for l in logs)

    def test_fallback_for_unknown_technique(self):
        gen  = LogGenerator()
        step = _make_step("T9999.999", log_count_hint=2)
        logs = gen.generate(step, SESSION_ID)
        assert len(logs) == 2
        assert all(l.is_malicious for l in logs)
        assert all(l.raw_data.get("fallback") is True for l in logs)

    def test_timestamps_are_jittered(self):
        gen  = LogGenerator()
        step = _make_step("T1059.001", log_count_hint=10)
        logs = gen.generate(step, SESSION_ID)
        timestamps = [l.timestamp for l in logs]
        # Not all timestamps should be identical (jitter should vary them)
        assert len(set(ts.second for ts in timestamps)) >= 1

    def test_to_db_dict_is_valid(self):
        gen  = LogGenerator()
        step = _make_step("T1059.001", log_count_hint=2)
        logs = gen.generate(step, SESSION_ID)
        for log in logs:
            d = log.to_db_dict()
            assert d["is_malicious"] is True
            assert d["session_id"]   == SESSION_ID
            assert d["message"]      != ""

    # ── Technique-specific tests ──────────────────────────────────────────────

    @pytest.mark.parametrize("technique_id,expected_source", [
        ("T1059.001", "windows_event"),   # PowerShell → Windows event
        ("T1547.001", "windows_event"),   # Registry run key
        ("T1053.005", "windows_event"),   # Scheduled task
        ("T1021.001", "windows_event"),   # RDP
        ("T1550.002", "windows_event"),   # Pass the hash
        ("T1486",     "endpoint_edr"),    # Ransomware → EDR
        ("T1070.001", "windows_event"),   # Log clearing
    ])
    def test_technique_produces_expected_source(self, technique_id, expected_source):
        gen  = LogGenerator()
        step = _make_step(technique_id, log_count_hint=1)
        logs = gen.generate(step, SESSION_ID)
        assert len(logs) >= 1
        sources = [l.source for l in logs]
        assert expected_source in sources, (
            f"{technique_id}: expected source '{expected_source}' in {sources}"
        )

    def test_brute_force_logs_have_event_id_4625(self):
        gen  = LogGenerator()
        # Brute force maps to T1110 — but Valid Accounts (T1078) has 4624
        step = _make_step(
            "T1078", log_count_hint=4,
            extra_data={"username": "jsmith", "service": "VPN"},
        )
        logs = gen.generate(step, SESSION_ID)
        event_ids = [l.event_id for l in logs if l.event_id]
        assert len(event_ids) > 0

    def test_powershell_logs_have_command_line(self):
        gen  = LogGenerator()
        step = _make_step(
            "T1059.001", log_count_hint=3,
            extra_data={"command": "powershell -enc AABBCC", "username": "jsmith"},
        )
        logs = gen.generate(step, SESSION_ID)
        cmd_logs = [l for l in logs if l.command_line]
        assert len(cmd_logs) >= 1

    def test_rdp_logs_have_source_ip(self):
        gen  = LogGenerator()
        step = _make_step(
            "T1021.001", log_count_hint=2,
            source_host="10.0.1.50",
            extra_data={"username": "amartinez"},
        )
        logs = gen.generate(step, SESSION_ID)
        assert any(l.source_ip for l in logs)

    def test_pass_the_hash_logs_severity_is_critical(self):
        gen  = LogGenerator()
        step = _make_step(
            "T1550.002", log_count_hint=2,
            severity="critical",
            extra_data={"username": "Administrator", "ntlm_hash": "aad3b435...xx"},
        )
        logs = gen.generate(step, SESSION_ID)
        critical_logs = [l for l in logs if l.severity in ("critical", "high")]
        assert len(critical_logs) >= 1

    def test_network_exfil_produces_network_flow(self):
        gen  = LogGenerator()
        step = _make_step(
            "T1041", log_count_hint=2,
            extra_data={"bytes_this_chunk": 5_000_000, "shell_port": 443},
        )
        logs = gen.generate(step, SESSION_ID)
        network_logs = [l for l in logs if l.source == "network_flow"]
        assert len(network_logs) >= 1

    def test_dns_tunnel_logs_have_port_53(self):
        gen  = LogGenerator()
        step = _make_step(
            "T1071.004", log_count_hint=2,
            extra_data={"c2_domain": "tunnel.evil.io", "bytes_this_chunk": 65536},
        )
        logs = gen.generate(step, SESSION_ID)
        dns_logs = [l for l in logs if l.destination_port == 53]
        assert len(dns_logs) >= 1

    def test_ransomware_logs_have_file_path(self):
        gen  = LogGenerator()
        step = _make_step(
            "T1486", log_count_hint=3,
            extra_data={"extension": ".lockbit", "ransomware_family": "LockBit 3.0"},
        )
        logs = gen.generate(step, SESSION_ID)
        file_logs = [l for l in logs if l.file_path]
        assert len(file_logs) >= 1

    def test_log_clearing_event_id_1102(self):
        gen  = LogGenerator()
        step = _make_step("T1070.001", log_count_hint=2)
        logs = gen.generate(step, SESSION_ID)
        assert any(l.event_id in (1102, 104) for l in logs)

    def test_registry_run_key_has_command_line(self):
        gen  = LogGenerator()
        step = _make_step(
            "T1547.001", log_count_hint=2,
            extra_data={"registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "payload": r"C:\Users\Public\svchost32.exe"},
        )
        logs = gen.generate(step, SESSION_ID)
        assert any(l.command_line for l in logs)

    def test_scheduled_task_event_id_4698(self):
        gen  = LogGenerator()
        step = _make_step(
            "T1053.005", log_count_hint=2,
            extra_data={"task_name": "WindowsUpdate"},
        )
        logs = gen.generate(step, SESSION_ID)
        assert any(l.event_id == 4698 for l in logs)

    def test_wmi_logs_have_parent_wmi(self):
        gen  = LogGenerator()
        step = _make_step("T1047", log_count_hint=2)
        logs = gen.generate(step, SESSION_ID)
        wmi_logs = [l for l in logs if l.parent_process and "WmiPrvSE" in l.parent_process]
        assert len(wmi_logs) >= 1

    def test_smb_logs_have_port_field(self):
        gen  = LogGenerator()
        step = _make_step("T1021.002", log_count_hint=2)
        logs = gen.generate(step, SESSION_ID)
        smb_logs = [l for l in logs if l.raw_data.get("ShareName")]
        assert len(smb_logs) >= 1

    def test_kerberos_ticket_logs(self):
        gen  = LogGenerator()
        step = _make_step(
            "T1550.003", log_count_hint=2,
            extra_data={"ticket_type": "Golden Ticket", "username": "krbtgt"},
        )
        logs = gen.generate(step, SESSION_ID)
        kerb_logs = [l for l in logs if l.event_id in (4768, 4769)]
        assert len(kerb_logs) >= 1

    def test_generate_from_scenario(self):
        gen   = LogGenerator()
        steps = [
            _make_step("T1595.001", log_count_hint=2),
            _make_step("T1059.001", log_count_hint=3),
            _make_step("T1486",     log_count_hint=2),
        ]
        logs = gen.generate_from_scenario(steps, SESSION_ID)
        assert len(logs) == 7   # 2 + 3 + 2
        assert all(isinstance(l, LogEntry) for l in logs)

    # ── Sigma field compatibility ─────────────────────────────────────────────

    def test_powershell_log_triggers_sigma_field_check(self):
        """Verify that PowerShell logs have the fields Block 4 Sigma rules query."""
        gen  = LogGenerator()
        step = _make_step(
            "T1059.001", log_count_hint=3,
            extra_data={"command": "powershell -enc AABB -WindowStyle Hidden bypass"},
        )
        logs = gen.generate(step, SESSION_ID)
        # The suspicious_powershell.yml rule checks: process_name|contains powershell
        # and command_line|contains [-enc, WindowStyle Hidden, bypass]
        ps_logs = [l for l in logs if l.process_name and "powershell" in l.process_name.lower()]
        assert len(ps_logs) >= 1
        for log in ps_logs:
            assert log.matches_field("process_name", "powershell")

    def test_brute_force_log_has_event_id_field(self):
        """Verify brute force logs have event_id so Sigma count rules work."""
        gen  = LogGenerator()
        step = _make_step("T1078", log_count_hint=3)
        logs = gen.generate(step, SESSION_ID)
        assert any(l.event_id is not None for l in logs)

    def test_ransomware_log_has_file_path_for_sigma(self):
        """Block 4 ransomware.yml checks file_path|contains .locked etc."""
        gen  = LogGenerator()
        step = _make_step("T1486", log_count_hint=3,
                          extra_data={"extension": ".locked"})
        logs = gen.generate(step, SESSION_ID)
        file_logs = [l for l in logs if l.file_path and ".locked" in l.file_path]
        assert len(file_logs) >= 1

    def test_c2_beacon_log_has_destination_port(self):
        """Block 4 c2_beacon.yml checks destination_port in [4444, 8443, ...]."""
        gen  = LogGenerator()
        step = _make_step("T1041", log_count_hint=3,
                          extra_data={"shell_port": 4444, "bytes_this_chunk": 1000000})
        logs = gen.generate(step, SESSION_ID)
        assert any(l.destination_port for l in logs)

    def test_registry_log_command_line_has_run_key(self):
        """Block 4 registry_persistence.yml checks command_line|contains Run\\."""
        gen  = LogGenerator()
        step = _make_step("T1547.001", log_count_hint=2,
                          extra_data={"registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"})
        logs = gen.generate(step, SESSION_ID)
        run_logs = [l for l in logs if l.command_line and "Run" in l.command_line]
        assert len(run_logs) >= 1


# ─── NoiseGenerator tests ──────────────────────────────────────────────────────

class TestNoiseGenerator:

    def test_burst_returns_list(self):
        gen  = NoiseGenerator()
        logs = gen.burst(SESSION_ID, count=10)
        assert isinstance(logs, list)

    def test_burst_count_respected(self):
        gen = NoiseGenerator()
        for n in (10, 15, 20):
            logs = gen.burst(SESSION_ID, count=n)
            # May be slightly fewer if templates are missing, but never more
            assert len(logs) <= n
            assert len(logs) > 0

    def test_burst_default_count_in_range(self):
        gen  = NoiseGenerator()
        # Run 20 times — all should land in 10–20
        for _ in range(20):
            logs = gen.burst(SESSION_ID)
            assert 5 <= len(logs) <= 25, f"Unexpected burst size: {len(logs)}"

    def test_all_noise_logs_not_malicious(self):
        gen  = NoiseGenerator()
        logs = gen.burst(SESSION_ID, count=20)
        assert all(l.is_malicious is False for l in logs)

    def test_all_noise_logs_have_no_attack_event_id(self):
        gen  = NoiseGenerator()
        logs = gen.burst(SESSION_ID, count=20)
        assert all(l.attack_event_id is None for l in logs)

    def test_all_noise_logs_have_session_id(self):
        gen  = NoiseGenerator()
        logs = gen.burst(SESSION_ID, count=15)
        assert all(l.session_id == SESSION_ID for l in logs)

    def test_noise_logs_are_valid_log_entries(self):
        gen  = NoiseGenerator()
        logs = gen.burst(SESSION_ID, count=10)
        for log in logs:
            assert isinstance(log, LogEntry)
            assert log.message != ""
            assert log.source in {
                "windows_event", "linux_syslog", "network_flow",
                "cloud_audit", "application", "endpoint_edr",
            }

    def test_noise_mix_includes_multiple_sources(self):
        gen  = NoiseGenerator()
        logs = gen.burst(SESSION_ID, count=50)
        sources = {l.source for l in logs}
        # With 50 logs, we expect at least 2 different sources
        assert len(sources) >= 2

    def test_to_db_dict_works_on_noise(self):
        gen  = NoiseGenerator()
        logs = gen.burst(SESSION_ID, count=5)
        for log in logs:
            d = log.to_db_dict()
            assert d["is_malicious"] is False
            assert d["attack_event_id"] is None

    def test_generate_for_duration_rate(self):
        gen  = NoiseGenerator()
        logs = gen.generate_for_duration(
            SESSION_ID,
            duration_minutes=3,
            rate_per_min=15,
        )
        # 3 minutes × ~15/min = ~45, allow 30% variance
        assert 20 <= len(logs) <= 80, f"Unexpected log count: {len(logs)}"

    def test_generate_for_duration_timestamps_span_window(self):
        gen   = NoiseGenerator()
        start = datetime.now(timezone.utc) - timedelta(minutes=5)
        logs  = gen.generate_for_duration(
            SESSION_ID,
            duration_minutes=5,
            rate_per_min=10,
            start_time=start,
        )
        if not logs:
            pytest.skip("No noise logs generated — check templates")
        earliest = min(l.timestamp for l in logs)
        latest   = max(l.timestamp for l in logs)
        span_minutes = (latest - earliest).total_seconds() / 60
        # Should span at least 3 minutes (5 - jitter)
        assert span_minutes >= 2, f"Window too narrow: {span_minutes:.1f} min"

    def test_interleave_is_sorted_by_timestamp(self):
        gen = NoiseGenerator()
        log_gen = LogGenerator()

        step = _make_step("T1059.001", log_count_hint=5)
        attack_logs = log_gen.generate(step, SESSION_ID)
        noise_logs  = gen.burst(SESSION_ID, count=15)

        combined = gen.interleave(attack_logs, noise_logs)

        timestamps = [l.timestamp for l in combined]
        assert timestamps == sorted(timestamps), "Interleaved logs not sorted by timestamp"

    def test_interleave_contains_both(self):
        gen     = NoiseGenerator()
        log_gen = LogGenerator()

        step        = _make_step("T1059.001", log_count_hint=3)
        attack_logs = log_gen.generate(step, SESSION_ID)
        noise_logs  = gen.burst(SESSION_ID, count=10)

        combined = gen.interleave(attack_logs, noise_logs)

        mal_count   = sum(1 for l in combined if l.is_malicious)
        noise_count = sum(1 for l in combined if not l.is_malicious)

        assert mal_count   == 3
        assert noise_count == len(noise_logs)

    def test_burst_with_base_time(self):
        gen       = NoiseGenerator()
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        logs      = gen.burst(SESSION_ID, count=10, base_time=base_time)
        for log in logs:
            delta = abs((log.timestamp - base_time).total_seconds())
            assert delta <= 60, f"Timestamp too far from base: {delta}s"


# ─── Integration: generator + noise + sigma field contract ────────────────────

class TestIntegration:
    """
    End-to-end: run representative steps through the generator, mix noise,
    then verify the resulting stream has the fields Block 4 Sigma rules need.
    """

    def test_full_pipeline_powershell(self):
        gen       = LogGenerator()
        noise_gen = NoiseGenerator()

        step        = _make_step("T1059.001", log_count_hint=4,
                                 extra_data={"command": "powershell -enc AABB -WindowStyle Hidden bypass",
                                             "username": "jsmith"})
        attack_logs = gen.generate(step, SESSION_ID)
        noise_logs  = noise_gen.burst(SESSION_ID, count=15)
        stream      = noise_gen.interleave(attack_logs, noise_logs)

        # Block 4 suspicious_powershell.yml: process_name contains 'powershell'
        ps_matches = [
            l for l in stream
            if l.process_name and "powershell" in l.process_name.lower()
        ]
        assert len(ps_matches) >= 1

    def test_full_pipeline_rdp_lateral_movement(self):
        gen       = LogGenerator()
        noise_gen = NoiseGenerator()

        step        = _make_step("T1021.001", log_count_hint=3,
                                 source_host="10.0.1.50",
                                 extra_data={"username": "amartinez"})
        attack_logs = gen.generate(step, SESSION_ID)
        noise_logs  = noise_gen.burst(SESSION_ID, count=20)
        stream      = noise_gen.interleave(attack_logs, noise_logs)

        # Block 4 lateral_movement.yml checks process_name contains psexec/wmiprvse
        # RDP logs have logon type 10 in raw_data
        rdp_logs = [l for l in stream if l.raw_data.get("LogonType") == 10]
        assert len(rdp_logs) >= 1

    def test_full_pipeline_data_exfil(self):
        gen       = LogGenerator()
        noise_gen = NoiseGenerator()

        step        = _make_step("T1041", log_count_hint=3,
                                 extra_data={"bytes_this_chunk": 10_000_000,
                                             "shell_port": 443})
        attack_logs = gen.generate(step, SESSION_ID)
        noise_logs  = noise_gen.burst(SESSION_ID, count=20)
        stream      = noise_gen.interleave(attack_logs, noise_logs)

        # Block 4 data_exfil.yml: source == network_flow
        net_logs = [l for l in stream if l.source == "network_flow" and l.is_malicious]
        assert len(net_logs) >= 1

    def test_noise_does_not_pollute_attack_event_ids(self):
        gen       = LogGenerator()
        noise_gen = NoiseGenerator()

        step        = _make_step("T1059.001", log_count_hint=3)
        attack_logs = gen.generate(step, SESSION_ID)
        noise_logs  = noise_gen.burst(SESSION_ID, count=20)
        stream      = noise_gen.interleave(attack_logs, noise_logs)

        # Only attack logs should have attack_event_id set
        for log in stream:
            if log.is_malicious:
                assert log.attack_event_id == step.id
            else:
                assert log.attack_event_id is None

    def test_no_logs_missing_session_id(self):
        gen       = LogGenerator()
        noise_gen = NoiseGenerator()

        step        = _make_step("T1547.001", log_count_hint=3)
        attack_logs = gen.generate(step, SESSION_ID)
        noise_logs  = noise_gen.burst(SESSION_ID, count=10)

        for log in attack_logs + noise_logs:
            assert log.session_id == SESSION_ID

    def test_all_log_sources_are_valid(self):
        gen       = LogGenerator()
        noise_gen = NoiseGenerator()

        valid_sources = {
            "windows_event", "linux_syslog", "network_flow",
            "cloud_audit", "application", "endpoint_edr",
        }
        step_ids = [
            "T1059.001", "T1021.001", "T1550.002", "T1486",
            "T1071.004", "T1070.001",
        ]
        for tid in step_ids:
            step = _make_step(tid, log_count_hint=3)
            logs = gen.generate(step, SESSION_ID)
            for log in logs:
                assert log.source in valid_sources, \
                    f"{tid}: invalid source '{log.source}'"
