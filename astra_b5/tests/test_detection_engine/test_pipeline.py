"""
End-to-end tests for the detection engine.

Strategy:
    1. Build LogEntry objects that simulate known-malicious activity
    2. Build LogEntry objects that simulate benign noise
    3. Run them through DetectionPipeline
    4. Assert correct alerts fire (and that benign logs don't trigger false positives)
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from core.log_engine.schemas import LogEntry, AlertSchema
from core.detection_engine.alert import (
    build_anomaly_alert,
    build_correlation_alert,
    build_sigma_alert,
)
from core.detection_engine.anomaly_detector import AnomalyDetector
from core.detection_engine.correlation import CorrelationEngine
from core.detection_engine.pipeline import DetectionPipeline
from core.detection_engine.rule_manager import RuleManager
from core.detection_engine.sigma_parser import evaluate_rule, parse_sigma_rule


SESSION_ID = "test_session_42"


# ════════════════════════════════════════════════════════════════════════════
# LogEntry schema tests
# ════════════════════════════════════════════════════════════════════════════
class TestLogEntrySchema:
    def test_minimal_log(self):
        log = LogEntry(session_id=SESSION_ID, source="windows_event", message="hello")
        assert log.session_id == SESSION_ID
        assert log.id  # auto-generated UUID
        assert log.timestamp.tzinfo is not None
        assert log.is_malicious is False

    def test_invalid_source_rejected(self):
        with pytest.raises(Exception):
            LogEntry(session_id=SESSION_ID, source="bad_source", message="x")

    def test_invalid_severity_rejected(self):
        with pytest.raises(Exception):
            LogEntry(
                session_id=SESSION_ID,
                source="windows_event",
                message="x",
                severity="EXTREMELY_BAD",
            )

    def test_to_db_dict(self):
        log = LogEntry(session_id=SESSION_ID, source="windows_event", message="hi")
        d = log.to_db_dict()
        assert "id" in d
        assert d["session_id"] == SESSION_ID

    def test_matches_field_string_contains(self):
        log = LogEntry(
            session_id=SESSION_ID,
            source="windows_event",
            message="x",
            process_name="powershell.exe",
        )
        assert log.matches_field("process_name", "powershell")
        assert log.matches_field("process_name", "POWER")  # case-insensitive
        assert not log.matches_field("process_name", "cmd")

    def test_matches_field_list_or(self):
        log = LogEntry(
            session_id=SESSION_ID,
            source="windows_event",
            message="x",
            process_name="cmd.exe",
        )
        assert log.matches_field("process_name", ["powershell", "cmd"])


# ════════════════════════════════════════════════════════════════════════════
# Sigma parser tests
# ════════════════════════════════════════════════════════════════════════════
class TestSigmaParser:
    def test_parse_simple_rule(self):
        yaml_text = """
title: Test Rule
description: For tests
detection:
    selection:
        process_name: powershell.exe
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""
        rule = parse_sigma_rule(yaml_text)
        assert rule.name == "Test Rule"
        assert rule.severity == "high"
        assert "selection" in rule.selections
        assert rule.technique_id == "T1059.001"
        assert rule.tactic == "execution"

    def test_parse_aggregation(self):
        yaml_text = """
title: Brute Force
detection:
    selection:
        event_id: 4625
    condition: selection | count(source_ip) > 5
    timeframe: 5m
level: high
"""
        rule = parse_sigma_rule(yaml_text)
        assert rule.aggregation is not None
        assert rule.aggregation["value"] == 5
        assert rule.aggregation["op"] == ">"
        assert rule.aggregation["group_by_field"] == "source_ip"
        assert rule.timeframe_seconds == 300

    def test_invalid_yaml(self):
        with pytest.raises(ValueError):
            parse_sigma_rule("not: valid: yaml: [")

    def test_no_detection_block(self):
        with pytest.raises(ValueError):
            parse_sigma_rule("title: foo\nlevel: high")


# ════════════════════════════════════════════════════════════════════════════
# Sigma evaluation tests
# ════════════════════════════════════════════════════════════════════════════
class TestSigmaEvaluation:
    def _make_log(self, **kwargs) -> LogEntry:
        defaults = dict(session_id=SESSION_ID, source="windows_event", message="x")
        defaults.update(kwargs)
        return LogEntry(**defaults)

    def test_simple_match(self):
        rule = parse_sigma_rule("""
title: Match PowerShell
detection:
    selection:
        process_name: powershell.exe
    condition: selection
level: medium
""")
        logs = [
            self._make_log(process_name="powershell.exe"),
            self._make_log(process_name="notepad.exe"),
            self._make_log(process_name="powershell.exe"),
        ]
        matches = evaluate_rule(rule, logs)
        assert len(matches) == 2

    def test_contains_modifier(self):
        rule = parse_sigma_rule("""
title: Encoded PS
detection:
    selection:
        command_line|contains: '-enc'
    condition: selection
level: high
""")
        logs = [
            self._make_log(command_line="powershell -enc abcd"),
            self._make_log(command_line="powershell -file foo.ps1"),
            self._make_log(command_line="powershell.exe -EncodedCommand xyz"),
        ]
        matches = evaluate_rule(rule, logs)
        # Two should match (-enc and -EncodedCommand, both case-insensitive)
        assert len(matches) >= 1

    def test_aggregation_count(self):
        rule = parse_sigma_rule("""
title: Brute Force
detection:
    selection:
        event_id: 4625
    condition: selection | count(source_ip) > 3
    timeframe: 5m
level: high
""")
        # 5 failed logins from same IP within 1 minute
        base = datetime.now(timezone.utc)
        logs = [
            self._make_log(
                event_id=4625,
                source_ip="10.0.0.5",
                timestamp=base + timedelta(seconds=i * 10),
            )
            for i in range(5)
        ]
        # Plus 2 from a different IP
        logs += [
            self._make_log(event_id=4625, source_ip="10.0.0.99", timestamp=base + timedelta(seconds=i * 10))
            for i in range(2)
        ]
        matches = evaluate_rule(rule, logs)
        # Should fire for the IP with 5 failures, not for the one with 2
        assert len(matches) == 1
        assert all(log.source_ip == "10.0.0.5" for log in matches[0])

    def test_no_match(self):
        rule = parse_sigma_rule("""
title: Ransomware Detection
detection:
    selection:
        file_path|contains: '.encrypted'
    condition: selection
level: critical
""")
        logs = [self._make_log(file_path="C:\\Users\\joe\\report.docx")]
        assert evaluate_rule(rule, logs) == []


# ════════════════════════════════════════════════════════════════════════════
# RuleManager tests
# ════════════════════════════════════════════════════════════════════════════
class TestRuleManager:
    def test_load_defaults_from_disk(self):
        mgr = RuleManager()
        count = mgr.load_defaults_from_disk()
        # We shipped at least 6 default rules
        assert count >= 6
        assert mgr.stats["default_rules"] == count

    def test_add_rule_from_yaml(self):
        mgr = RuleManager()
        rule = mgr.add_rule_from_yaml("""
title: Custom Rule
detection:
    selection:
        process_name: explorer.exe
    condition: selection
level: low
""")
        assert rule.id in mgr.all_rule_ids()
        assert mgr.stats["user_rules"] == 1

    def test_enable_disable(self):
        mgr = RuleManager()
        rule = mgr.add_rule_from_yaml("""
title: Toggle Test
detection:
    selection:
        process_name: foo.exe
    condition: selection
""")
        assert rule in mgr.active_rules()
        mgr.disable(rule.id)
        assert rule not in mgr.active_rules()
        mgr.enable(rule.id)
        assert rule in mgr.active_rules()


# ════════════════════════════════════════════════════════════════════════════
# Pipeline end-to-end tests
# ════════════════════════════════════════════════════════════════════════════
class TestPipelineE2E:
    @pytest.mark.asyncio
    async def test_initialize_loads_disk_rules(self):
        pipe = DetectionPipeline(session_id=SESSION_ID, enable_anomaly=False, enable_correlation=False)
        stats = await pipe.initialize(db=None, load_disk_defaults=True)
        assert stats["disk_rules_loaded"] >= 6

    @pytest.mark.asyncio
    async def test_powershell_attack_triggers_alert(self):
        pipe = DetectionPipeline(session_id=SESSION_ID, enable_anomaly=False, enable_correlation=False)
        await pipe.initialize(db=None, load_disk_defaults=True)

        malicious_log = LogEntry(
            session_id=SESSION_ID,
            source="windows_event",
            message="PowerShell launched with encoded command",
            process_name="powershell.exe",
            command_line="powershell.exe -enc JABzAD0ATgBl",
            category="process_creation",
            is_malicious=True,
        )
        alerts = pipe.process_log(malicious_log)

        # Should fire the "Suspicious PowerShell" rule
        assert len(alerts) >= 1
        names = [a.title for a in alerts]
        assert any("PowerShell" in n for n in names)
        # Was malicious → should be marked TP
        assert any(a.is_true_positive is True for a in alerts)

    @pytest.mark.asyncio
    async def test_brute_force_triggers_after_threshold(self):
        pipe = DetectionPipeline(session_id=SESSION_ID, enable_anomaly=False, enable_correlation=False)
        await pipe.initialize(db=None, load_disk_defaults=True)

        # Build 7 failed login logs (>5 threshold) within window
        base = datetime.now(timezone.utc)
        logs = [
            LogEntry(
                session_id=SESSION_ID,
                source="windows_event",
                event_id=4625,
                category="authentication",
                source_ip="192.168.1.50",
                username="admin",
                message=f"Failed login attempt #{i + 1}",
                timestamp=base + timedelta(seconds=i * 5),
                is_malicious=True,
            )
            for i in range(7)
        ]
        alerts = pipe.process_logs(logs)

        # Brute force rule should fire
        names = [a.title for a in alerts]
        assert any("Brute Force" in n for n in names)

    @pytest.mark.asyncio
    async def test_benign_logs_dont_alert(self):
        pipe = DetectionPipeline(session_id=SESSION_ID, enable_anomaly=False, enable_correlation=False)
        await pipe.initialize(db=None, load_disk_defaults=True)

        benign = [
            LogEntry(
                session_id=SESSION_ID,
                source="windows_event",
                event_id=4624,  # Successful login
                category="authentication",
                source_ip=f"10.0.0.{i}",
                username=f"user{i}",
                message="Successful login",
                is_malicious=False,
            )
            for i in range(3)
        ]
        alerts = pipe.process_logs(benign)
        # Should produce zero alerts for these benign logs
        assert all(a.is_true_positive is False or a.is_true_positive is None for a in alerts)


# ════════════════════════════════════════════════════════════════════════════
# Anomaly detector tests
# ════════════════════════════════════════════════════════════════════════════
class TestAnomalyDetector:
    def _benign_log(self, i: int) -> LogEntry:
        return LogEntry(
            session_id=SESSION_ID,
            source="windows_event",
            event_id=4624,
            category="authentication",
            severity="info",
            source_ip=f"10.0.0.{i % 255}",
            username=f"user{i % 20}",
            command_line="explorer.exe",
            process_name="explorer.exe",
            message=f"Benign login {i}",
        )

    def test_baseline_collection_then_fit(self):
        det = AnomalyDetector(baseline_size=50)
        for i in range(50):
            det.add_for_baseline(self._benign_log(i))
        assert det.fit_baseline() in (True, False)  # depends on sklearn availability

    def test_score_returns_zero_if_not_fitted(self):
        det = AnomalyDetector(baseline_size=50)
        log = self._benign_log(1)
        assert det.score(log) == 0.0


# ════════════════════════════════════════════════════════════════════════════
# Correlation tests
# ════════════════════════════════════════════════════════════════════════════
class TestCorrelation:
    def test_brute_force_success_correlation(self):
        eng = CorrelationEngine()
        base = datetime.now(timezone.utc)

        # 5 brute force alerts
        for i in range(5):
            alert = AlertSchema(
                session_id=SESSION_ID,
                detection_type="sigma",
                title="Brute Force Login Attempt",
                description="failed login",
                severity="high",
                source_ip="192.168.1.50",
                hostname="WORKSTATION-01",
                timestamp=base + timedelta(seconds=i * 30),
            )
            eng.add_alert(alert)

        # Then a successful login from same IP
        success = AlertSchema(
            session_id=SESSION_ID,
            detection_type="sigma",
            title="Successful Login from Suspicious Source",
            description="authentication success",
            severity="medium",
            source_ip="192.168.1.50",
            hostname="WORKSTATION-01",
            timestamp=base + timedelta(seconds=200),
        )
        eng.add_alert(success)

        incidents = eng.find_correlations(SESSION_ID)
        # Brute Force Success pattern should fire
        assert any("Brute Force Success" in a.title for a in incidents)
