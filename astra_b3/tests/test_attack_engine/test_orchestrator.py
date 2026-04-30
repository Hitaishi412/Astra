"""
tests/test_attack_engine/test_orchestrator.py
──────────────────────────────────────────────
Tests for Block 2: Kill Chain, Techniques, Scenarios, and Orchestrator.

Run with:
    cd warroom
    pip install pytest pytest-asyncio
    pytest tests/test_attack_engine/ -v
"""

from __future__ import annotations

import pytest
import asyncio
from typing import Generator

from config.constants import KillChainPhase, Difficulty, Severity
from core.attack_engine.techniques.base import AttackStep, BaseTechnique
from core.attack_engine.techniques.reconnaissance import ActivePortScan, VulnerabilityScanning, OSINTCredentialHarvest
from core.attack_engine.techniques.initial_access import (
    SpearphishingAttachment, SpearphishingLink, ExploitPublicApp, ValidAccounts, SoftwareSupplyChain
)
from core.attack_engine.techniques.execution import PowerShellExecution, CMDExecution, WMIExecution
from core.attack_engine.techniques.persistence import RegistryRunKey, ScheduledTask, CreateLocalAccount
from core.attack_engine.techniques.privilege_escalation import TokenImpersonation, SudoAbuse
from core.attack_engine.techniques.lateral_movement import RDPLateralMovement, SMBAdminShares, PassTheHash, PassTheTicket
from core.attack_engine.techniques.exfiltration import (
    DNSTunnelExfil, C2ChannelExfil, CloudStorageExfil,
    LogClearing, ObfuscatedFiles, TimeStomp,
    RansomwareEncryption, DataDestruction,
)
from core.attack_engine.kill_chain import KillChain
from core.attack_engine.scenarios.all_scenarios import (
    RansomwareScenario, APTEspionageScenario, InsiderThreatScenario,
    PhishingChainScenario, SupplyChainScenario, SCENARIO_MAP,
)
from core.attack_engine.orchestrator import AttackOrchestrator


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def context():
    return {
        "target_ip":     "10.0.1.50",
        "target_domain": "corp.internal",
        "scenario_id":   "test",
        "difficulty":    "medium",
    }


@pytest.fixture
def orchestrator():
    return AttackOrchestrator()


# ─── AttackStep data class ────────────────────────────────────────────────────

class TestAttackStep:
    def test_has_uuid(self):
        s = AttackStep()
        assert len(s.id) == 36   # UUID4 format

    def test_has_timestamp(self):
        s = AttackStep()
        assert s.timestamp is not None

    def test_defaults(self):
        s = AttackStep()
        assert s.success is True
        assert s.log_count_hint == 5
        assert s.extra_data == {}


# ─── BaseTechnique helpers ────────────────────────────────────────────────────

class TestBaseTechniqueHelpers:
    def test_fake_ip_internal(self):
        ip = BaseTechnique._fake_ip(internal=True)
        assert ip.startswith("10.0.")

    def test_fake_ip_external(self):
        ip = BaseTechnique._fake_ip(internal=False)
        parts = ip.split(".")
        assert len(parts) == 4

    def test_fake_hostname(self):
        h = BaseTechnique._fake_hostname("SRV")
        assert h.startswith("SRV-")
        assert len(h) == 9  # "SRV-" + 5 chars

    def test_success_rate_scales_with_difficulty(self):
        easy   = ActivePortScan(Difficulty.BEGINNER)
        expert = ActivePortScan(Difficulty.EXPERT)
        assert expert._success_rate() > easy._success_rate()

    def test_log_count_expert_lower_than_beginner(self):
        # Run many times to average out randomness
        beginner_avg = sum(ActivePortScan(Difficulty.BEGINNER)._log_count() for _ in range(50)) / 50
        expert_avg   = sum(ActivePortScan(Difficulty.EXPERT)._log_count() for _ in range(50)) / 50
        assert expert_avg < beginner_avg


# ─── Reconnaissance techniques ───────────────────────────────────────────────

class TestReconnaissanceTechniques:
    def test_port_scan_returns_step(self, context):
        tech = ActivePortScan()
        step = tech.execute(context)
        assert isinstance(step, AttackStep)
        assert step.technique_id == "T1595.001"
        assert step.tactic == "reconnaissance"
        assert step.success is True   # port scan always finds something
        assert "open_ports" in step.extra_data
        assert isinstance(step.extra_data["open_ports"], list)

    def test_port_scan_populates_context(self, context):
        ActivePortScan().execute(context)
        assert "open_ports" in context
        assert "target_ip" in context

    def test_vuln_scan_has_cve(self, context):
        step = VulnerabilityScanning().execute(context)
        assert "CVE" in step.extra_data["cve_checked"]

    def test_osint_creds_has_domain(self, context):
        step = OSINTCredentialHarvest().execute(context)
        assert step.extra_data["target_domain"] == "corp.internal"

    def test_all_recon_steps_have_phase(self, context):
        for TechClass in [ActivePortScan, VulnerabilityScanning, OSINTCredentialHarvest]:
            step = TechClass().execute(context)
            assert step.phase == KillChainPhase.RECONNAISSANCE.value


# ─── Initial access techniques ───────────────────────────────────────────────

class TestInitialAccessTechniques:
    def test_phishing_attachment_returns_step(self, context):
        step = SpearphishingAttachment().execute(context)
        assert isinstance(step, AttackStep)
        assert step.technique_id == "T1566.001"

    def test_phishing_populates_context_on_success(self, context):
        # Run 20 times — at least one should succeed with 75% rate
        for _ in range(20):
            c = dict(context)
            step = SpearphishingAttachment().execute(c)
            if step.success:
                assert "initial_access_user" in c
                assert "initial_access_host" in c
                return
        pytest.skip("All 20 runs failed — extremely unlikely but possible")

    def test_exploit_app_sets_shell_obtained(self, context):
        context["cve_found"] = "CVE-2021-44228"
        context["vuln_service"] = "Apache Log4j"
        # Run until success
        for _ in range(30):
            c = dict(context)
            step = ExploitPublicApp().execute(c)
            if step.success:
                assert c.get("shell_obtained") is True
                return

    def test_valid_accounts_uses_harvested_creds(self, context):
        context["harvested_credentials"] = ["jsmith"]
        step = ValidAccounts().execute(context)
        assert step.extra_data["username"] == "jsmith"

    def test_supply_chain_sets_method(self, context):
        for _ in range(20):
            c = dict(context)
            step = SoftwareSupplyChain().execute(c)
            if step.success:
                assert c.get("initial_access_method") == "supply_chain"
                return


# ─── Execution techniques ────────────────────────────────────────────────────

class TestExecutionTechniques:
    def test_powershell_returns_step(self, context):
        context["initial_access_host"] = "DESKTOP-ABC12"
        step = PowerShellExecution().execute(context)
        assert step.technique_id == "T1059.001"
        assert "command" in step.extra_data

    def test_expert_powershell_is_obfuscated(self, context):
        context["initial_access_host"] = "DESKTOP-ABC12"
        step = PowerShellExecution(Difficulty.EXPERT).execute(context)
        assert step.extra_data.get("obfuscated") is True

    def test_cmd_execution_has_command(self, context):
        step = CMDExecution().execute(context)
        assert "command" in step.extra_data

    def test_wmi_has_different_src_tgt(self, context):
        context["initial_access_host"] = "DESKTOP-ABC12"
        step = WMIExecution().execute(context)
        assert step.source_host != step.target_host


# ─── Persistence techniques ──────────────────────────────────────────────────

class TestPersistenceTechniques:
    def test_registry_run_key_returns_step(self, context):
        step = RegistryRunKey().execute(context)
        assert step.technique_id == "T1547.001"
        assert "registry_key" in step.extra_data

    def test_scheduled_task_has_trigger(self, context):
        step = ScheduledTask().execute(context)
        assert "trigger" in step.extra_data

    def test_local_account_sets_backdoor(self, context):
        for _ in range(20):
            c = dict(context)
            step = CreateLocalAccount().execute(c)
            if step.success:
                assert "backdoor_account" in c
                return


# ─── Lateral movement techniques ─────────────────────────────────────────────

class TestLateralMovementTechniques:
    def test_rdp_different_hosts(self, context):
        context["initial_access_host"] = "DESKTOP-AAAAA"
        step = RDPLateralMovement().execute(context)
        assert step.source_host != step.target_host

    def test_pass_hash_has_ntlm_hash(self, context):
        step = PassTheHash().execute(context)
        assert "ntlm_hash" in step.extra_data
        assert "..." in step.extra_data["ntlm_hash"]   # truncated

    def test_pass_ticket_has_type(self, context):
        step = PassTheTicket().execute(context)
        assert step.extra_data["ticket_type"] in ("Golden Ticket", "Silver Ticket")

    def test_smb_shares_has_port_445(self, context):
        step = SMBAdminShares().execute(context)
        assert step.extra_data["port"] == 445


# ─── Exfiltration techniques ─────────────────────────────────────────────────

class TestExfiltrationTechniques:
    def test_dns_tunnel_has_c2(self, context):
        step = DNSTunnelExfil().execute(context)
        assert "c2_domain" in step.extra_data
        assert step.extra_data["encoded"] is True

    def test_c2_exfil_data_type(self, context):
        step = C2ChannelExfil().execute(context)
        assert "data_type" in step.extra_data
        assert "size_mb" in step.extra_data

    def test_cloud_exfil_service(self, context):
        step = CloudStorageExfil().execute(context)
        assert "service" in step.extra_data


# ─── Defense evasion techniques ──────────────────────────────────────────────

class TestDefenseEvasionTechniques:
    def test_log_clearing_has_logs_list(self, context):
        step = LogClearing().execute(context)
        assert "logs_cleared" in step.extra_data
        assert isinstance(step.extra_data["logs_cleared"], list)

    def test_obfuscation_has_method(self, context):
        step = ObfuscatedFiles().execute(context)
        assert "method" in step.extra_data

    def test_timestomp_has_files(self, context):
        step = TimeStomp().execute(context)
        assert "files" in step.extra_data


# ─── Impact techniques ────────────────────────────────────────────────────────

class TestImpactTechniques:
    def test_ransomware_has_family(self, context):
        step = RansomwareEncryption().execute(context)
        assert "ransomware_family" in step.extra_data
        assert step.severity == Severity.CRITICAL.value

    def test_destruction_has_method(self, context):
        step = DataDestruction().execute(context)
        assert "method" in step.extra_data


# ─── Kill chain state machine ─────────────────────────────────────────────────

class TestKillChain:
    def test_initial_state(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE, KillChainPhase.DELIVERY])
        assert kc.state == "idle"
        assert kc.current_phase == KillChainPhase.RECONNAISSANCE

    def test_start(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE])
        kc.start()
        assert kc.state == "running"

    def test_cannot_start_twice(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE])
        kc.start()
        with pytest.raises(RuntimeError):
            kc.start()

    def test_record_step(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE])
        kc.start()
        step = AttackStep(phase="reconnaissance", technique_id="T1595.001",
                          technique_name="Port Scan", tactic="reconnaissance",
                          description="Scanned", success=True)
        kc.record_step(step)
        assert kc.current_result.step_count == 1
        assert kc.current_result.successful_steps == 1

    def test_should_advance_after_success(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE, KillChainPhase.DELIVERY])
        kc.start()
        step = AttackStep(success=True)
        kc.record_step(step)
        assert kc.should_advance() is True

    def test_advance_moves_to_next_phase(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE, KillChainPhase.DELIVERY])
        kc.start()
        kc.record_step(AttackStep(success=True))
        kc.advance()
        assert kc.current_phase == KillChainPhase.DELIVERY

    def test_advance_on_last_phase_completes(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE])
        kc.start()
        kc.record_step(AttackStep(success=True))
        advanced = kc.advance()
        assert advanced is False
        assert kc.state == "complete"
        assert kc.is_terminal is True

    def test_abort(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE])
        kc.start()
        kc.abort()
        assert kc.state == "aborted"
        assert kc.is_terminal is True

    def test_progress_pct(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE, KillChainPhase.DELIVERY,
                         KillChainPhase.EXPLOITATION])
        kc.start()
        kc.record_step(AttackStep(success=True))
        kc.advance()
        assert kc.progress_pct == pytest.approx(33.3, abs=0.2)

    def test_all_steps_aggregation(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE, KillChainPhase.DELIVERY])
        kc.start()
        kc.record_step(AttackStep(success=True))
        kc.record_step(AttackStep(success=False))
        assert kc.total_steps == 2
        assert len(kc.all_steps) == 2

    def test_summary_dict(self):
        kc = KillChain([KillChainPhase.RECONNAISSANCE])
        kc.start()
        summary = kc.summary()
        assert "state" in summary
        assert "progress_pct" in summary
        assert "phases_total" in summary


# ─── Scenario classes ─────────────────────────────────────────────────────────

class TestScenarios:
    @pytest.mark.parametrize("ScenClass", [
        RansomwareScenario, APTEspionageScenario, InsiderThreatScenario,
        PhishingChainScenario, SupplyChainScenario,
    ])
    def test_scenario_produces_steps(self, ScenClass):
        scenario = ScenClass(difficulty=Difficulty.MEDIUM)
        steps = list(scenario.run())
        assert len(steps) > 0, f"{ScenClass.__name__} produced no steps"

    @pytest.mark.parametrize("ScenClass", [
        RansomwareScenario, APTEspionageScenario, InsiderThreatScenario,
        PhishingChainScenario, SupplyChainScenario,
    ])
    def test_all_steps_have_required_fields(self, ScenClass):
        scenario = ScenClass(difficulty=Difficulty.MEDIUM)
        for step in scenario.run():
            assert step.technique_id,   f"technique_id empty in {ScenClass.__name__}"
            assert step.technique_name, f"technique_name empty in {ScenClass.__name__}"
            assert step.tactic,         f"tactic empty in {ScenClass.__name__}"
            assert step.phase,          f"phase empty in {ScenClass.__name__}"
            assert step.description,    f"description empty in {ScenClass.__name__}"
            assert step.step_number > 0, f"step_number not set in {ScenClass.__name__}"

    @pytest.mark.parametrize("ScenClass", [
        RansomwareScenario, APTEspionageScenario, InsiderThreatScenario,
        PhishingChainScenario, SupplyChainScenario,
    ])
    def test_steps_numbered_sequentially(self, ScenClass):
        scenario = ScenClass()
        steps = list(scenario.run())
        numbers = [s.step_number for s in steps]
        assert numbers == list(range(1, len(steps) + 1))

    def test_ransomware_has_encryption_step(self):
        scenario = RansomwareScenario()
        steps = list(scenario.run())
        techniques = [s.technique_id for s in steps]
        assert "T1486" in techniques   # Ransomware encryption

    def test_apt_has_dns_exfil(self):
        scenario = APTEspionageScenario()
        steps = list(scenario.run())
        techniques = [s.technique_id for s in steps]
        assert "T1071.004" in techniques   # DNS tunneling

    def test_insider_threat_has_cloud_exfil(self):
        scenario = InsiderThreatScenario()
        steps = list(scenario.run())
        techniques = [s.technique_id for s in steps]
        assert "T1567.002" in techniques   # Cloud storage exfil

    def test_scenario_mitre_techniques_list(self):
        scenario = RansomwareScenario()
        techniques = scenario.mitre_techniques
        assert len(techniques) > 0
        assert all(t.startswith("T") for t in techniques)

    def test_kill_chain_summary_after_run(self):
        scenario = InsiderThreatScenario()
        list(scenario.run())   # exhaust
        summary = scenario.kill_chain_summary
        assert summary["state"] == "complete"
        assert summary["progress_pct"] == 100.0

    @pytest.mark.parametrize("difficulty", [
        Difficulty.BEGINNER, Difficulty.MEDIUM, Difficulty.HARD, Difficulty.EXPERT
    ])
    def test_all_difficulties_run(self, difficulty):
        scenario = RansomwareScenario(difficulty=difficulty)
        steps = list(scenario.run())
        assert len(steps) > 0

    def test_scenario_registry_complete(self):
        expected = {"ransomware", "apt_espionage", "insider_threat", "phishing_chain", "supply_chain"}
        assert set(SCENARIO_MAP.keys()) == expected


# ─── Orchestrator ─────────────────────────────────────────────────────────────

class TestOrchestrator:
    def test_list_scenarios(self, orchestrator):
        scenarios = orchestrator.list_scenarios()
        assert "ransomware" in scenarios
        assert len(scenarios) == 5

    def test_run_scenario_returns_steps(self, orchestrator):
        steps = orchestrator.run_scenario("insider_threat", difficulty="medium")
        assert len(steps) > 0
        assert all(isinstance(s, AttackStep) for s in steps)

    def test_run_unknown_scenario_raises(self, orchestrator):
        with pytest.raises(ValueError, match="Unknown scenario"):
            orchestrator.run_scenario("not_a_real_scenario")

    def test_load_returns_metadata(self, orchestrator):
        meta = orchestrator.load("ransomware", difficulty="medium")
        assert meta["scenario_id"] == "ransomware"
        assert "phases" in meta
        assert "mitre_techniques" in meta
        assert meta["status"] == "loaded"

    def test_is_loaded_after_load(self, orchestrator):
        orchestrator.load("insider_threat")
        assert orchestrator.is_loaded is True

    def test_next_step_returns_step(self, orchestrator):
        orchestrator.load("insider_threat")
        step = orchestrator.next_step()
        assert isinstance(step, AttackStep)

    def test_next_step_returns_none_when_done(self, orchestrator):
        orchestrator.load("insider_threat")
        # Exhaust all steps
        results = []
        while True:
            step = orchestrator.next_step()
            if step is None:
                break
            results.append(step)
        assert len(results) > 0
        assert orchestrator.is_loaded is False

    def test_next_step_without_load_raises(self, orchestrator):
        with pytest.raises(RuntimeError, match="No scenario loaded"):
            orchestrator.next_step()

    def test_abort_clears_loaded(self, orchestrator):
        orchestrator.load("ransomware")
        orchestrator.abort()
        assert orchestrator.is_loaded is False

    def test_kill_chain_summary_while_loaded(self, orchestrator):
        orchestrator.load("ransomware")
        orchestrator.next_step()
        summary = orchestrator.kill_chain_summary
        assert summary is not None
        assert "state" in summary

    def test_campaign_context_while_loaded(self, orchestrator):
        orchestrator.load("ransomware", target_ip="192.168.1.10")
        ctx = orchestrator.campaign_context
        assert ctx is not None
        assert ctx["target_ip"] == "192.168.1.10"

    @pytest.mark.asyncio
    async def test_async_streaming(self, orchestrator):
        steps = []
        async for step in orchestrator.run_scenario_async(
            "insider_threat", step_delay_ms=0
        ):
            steps.append(step)
        assert len(steps) > 0
        assert all(isinstance(s, AttackStep) for s in steps)

    @pytest.mark.asyncio
    async def test_async_steps_ordered(self, orchestrator):
        steps = []
        async for step in orchestrator.run_scenario_async(
            "insider_threat", step_delay_ms=0
        ):
            steps.append(step)
        numbers = [s.step_number for s in steps]
        assert numbers == sorted(numbers)
