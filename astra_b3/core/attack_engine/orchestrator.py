"""
core/attack_engine/orchestrator.py
────────────────────────────────────
Master controller for the Attack Engine (Block 2).

This is the ONLY file that Block 3 (Log Engine), Block 5 (MITRE),
and the API routers need to import. Everything else is internal.

Public interface:
────────────────
    from core.attack_engine.orchestrator import AttackOrchestrator

    orchestrator = AttackOrchestrator()

    # Run a full scenario synchronously (for scripts/testing)
    steps = orchestrator.run_scenario("ransomware", difficulty="hard")

    # Run async (for API/WebSocket streaming)
    async for step in orchestrator.run_scenario_async("ransomware", session_id="..."):
        await log_engine.generate(step)
        await db.save_attack_event(step)

    # Single-step mode (dashboard "advance phase" button)
    orchestrator.load("ransomware", difficulty="medium")
    step = orchestrator.next_step()   # call once per button click
"""

from __future__ import annotations

import asyncio
from typing import AsyncGenerator, Generator, Optional, Any

from config.constants import Difficulty
from core.attack_engine.scenarios.all_scenarios import SCENARIO_MAP, BaseScenario
from core.attack_engine.techniques.base import AttackStep


class AttackOrchestrator:
    """
    Drives scenario execution and exposes three run modes:

    1. Batch     — run_scenario()       → list[AttackStep]   (sync, for scripts)
    2. Streaming — run_scenario_async() → AsyncGenerator      (for WebSocket / API)
    3. Stepwise  — load() + next_step() → one step at a time  (for dashboard button)
    """

    def __init__(self):
        self._active_scenario: Optional[BaseScenario] = None
        self._active_generator: Optional[Generator[AttackStep, None, None]] = None
        self._step_delay_ms:   int = 500    # delay between steps in streaming mode

    # ── Scenario resolution ───────────────────────────────────────────────────

    @staticmethod
    def list_scenarios() -> list[str]:
        return list(SCENARIO_MAP.keys())

    @staticmethod
    def _resolve(
        scenario_id: str,
        difficulty:  str = Difficulty.MEDIUM,
        target_ip:   str | None = None,
        target_domain: str = "corp.internal",
        extra_config:  dict | None = None,
    ) -> BaseScenario:
        cls = SCENARIO_MAP.get(scenario_id)
        if cls is None:
            raise ValueError(
                f"Unknown scenario '{scenario_id}'. "
                f"Available: {list(SCENARIO_MAP.keys())}"
            )
        return cls(
            difficulty=difficulty,
            target_ip=target_ip,
            target_domain=target_domain,
            extra_config=extra_config,
        )

    # ── Mode 1: Batch (sync) ──────────────────────────────────────────────────

    def run_scenario(
        self,
        scenario_id: str,
        difficulty:  str = Difficulty.MEDIUM,
        target_ip:   str | None = None,
        **kwargs,
    ) -> list[AttackStep]:
        """
        Execute an entire scenario synchronously.
        Returns all steps once the scenario is complete.

        Best for:  scripts, testing, report generation
        Not for:   real-time streaming to the dashboard
        """
        scenario = self._resolve(scenario_id, difficulty, target_ip, **kwargs)
        steps    = list(scenario.run())
        return steps

    # ── Mode 2: Async streaming ───────────────────────────────────────────────

    async def run_scenario_async(
        self,
        scenario_id:   str,
        difficulty:    str = Difficulty.MEDIUM,
        target_ip:     str | None = None,
        step_delay_ms: int = 500,
        **kwargs,
    ) -> AsyncGenerator[AttackStep, None]:
        """
        Async generator that yields one AttackStep at a time with a delay.
        Designed to feed a WebSocket stream.

        Usage:
            async for step in orchestrator.run_scenario_async("ransomware"):
                await ws_manager.broadcast(step.model_dump())
                await db.save_attack_event(step)
        """
        scenario = self._resolve(scenario_id, difficulty, target_ip, **kwargs)
        delay    = step_delay_ms / 1000.0

        for step in scenario.run():
            yield step
            if delay > 0:
                await asyncio.sleep(delay)

    # ── Mode 3: Stepwise (for dashboard button clicks) ────────────────────────

    def load(
        self,
        scenario_id: str,
        difficulty:  str = Difficulty.MEDIUM,
        target_ip:   str | None = None,
        **kwargs,
    ) -> dict:
        """
        Load a scenario without running it. Returns scenario metadata.
        Then call next_step() to execute one technique at a time.
        """
        self._active_scenario  = self._resolve(scenario_id, difficulty, target_ip, **kwargs)
        self._active_generator = self._active_scenario.run()
        return {
            "scenario_id":      scenario_id,
            "name":             self._active_scenario.NAME,
            "description":      self._active_scenario.DESCRIPTION,
            "phases":           [p.value for p in self._active_scenario.PHASES],
            "mitre_techniques": self._active_scenario.mitre_techniques,
            "difficulty":       difficulty,
            "target_ip":        self._active_scenario.target_ip,
            "status":           "loaded",
        }

    def next_step(self) -> Optional[AttackStep]:
        """
        Execute the next technique and return its AttackStep.
        Returns None when the scenario is complete.

        Raises RuntimeError if no scenario is loaded.
        """
        if self._active_generator is None:
            raise RuntimeError("No scenario loaded. Call load() first.")
        try:
            return next(self._active_generator)
        except StopIteration:
            self._active_scenario  = None
            self._active_generator = None
            return None

    def abort(self) -> None:
        """Abort the currently loaded scenario."""
        if self._active_scenario:
            self._active_scenario._kill_chain.abort()
        self._active_scenario  = None
        self._active_generator = None

    @property
    def is_loaded(self) -> bool:
        return self._active_generator is not None

    @property
    def kill_chain_summary(self) -> Optional[dict]:
        if self._active_scenario:
            return self._active_scenario.kill_chain_summary
        return None

    # ── Context snapshot (for dashboard state display) ────────────────────────

    @property
    def campaign_context(self) -> Optional[dict[str, Any]]:
        """Return the live campaign context dict (shared state between techniques)."""
        if self._active_scenario:
            return dict(self._active_scenario.context)
        return None
