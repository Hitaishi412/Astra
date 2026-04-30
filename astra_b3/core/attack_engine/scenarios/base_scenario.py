"""
core/attack_engine/scenarios/base_scenario.py
──────────────────────────────────────────────
Abstract base class every scenario inherits from.

A scenario is a curated sequence of techniques organised into kill chain phases.
It knows:
  - Which techniques to run in which order
  - How many steps per phase (configurable by difficulty)
  - The shared campaign context passed between techniques
  - How to yield AttackSteps one at a time (generator interface)

The orchestrator calls scenario.run() and gets back a stream of AttackSteps.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generator, Any

from config.constants import KillChainPhase, Difficulty
from core.attack_engine.kill_chain import KillChain
from core.attack_engine.techniques.base import BaseTechnique, AttackStep


class BaseScenario(ABC):
    """
    Subclasses define:
        SCENARIO_ID   = "ransomware"
        NAME          = "Ransomware Outbreak"
        DESCRIPTION   = "..."
        PHASES        = [KillChainPhase.DELIVERY, ...]

    And implement:
        _build_phase_techniques() → dict[KillChainPhase, list[BaseTechnique]]
    """

    SCENARIO_ID: str = ""
    NAME:        str = ""
    DESCRIPTION: str = ""
    PHASES:      list[KillChainPhase] = []

    def __init__(
        self,
        difficulty:  str = Difficulty.MEDIUM,
        target_ip:   str | None = None,
        target_domain: str = "corp.internal",
        extra_config: dict | None = None,
    ):
        self.difficulty    = difficulty
        self.target_ip     = target_ip or f"10.0.{__import__('random').randint(1,10)}.{__import__('random').randint(2,100)}"
        self.target_domain = target_domain
        self.extra_config  = extra_config or {}

        # Shared mutable state passed between all techniques
        self.context: dict[str, Any] = {
            "scenario_id":    self.SCENARIO_ID,
            "difficulty":     difficulty,
            "target_ip":      self.target_ip,
            "target_domain":  target_domain,
        }

        self._kill_chain = KillChain(phases=self.PHASES)
        self._step_counter = 0

    # ── Subclasses implement this ─────────────────────────────────────────────

    @abstractmethod
    def _build_phase_techniques(self) -> dict[KillChainPhase, list[BaseTechnique]]:
        """
        Return a mapping of phase → list of technique instances to run.
        Techniques are executed in list order within each phase.
        """
        ...

    # ── Public interface ──────────────────────────────────────────────────────

    def run(self) -> Generator[AttackStep, None, None]:
        """
        Generator that yields AttackStep objects one at a time.
        The orchestrator calls next() on this to drive the campaign.

        Each yielded step should be:
          1. Saved to DB as AttackEvent (Block 1 crud)
          2. Passed to Log Engine (Block 3) to generate log entries
          3. Passed to MITRE Mapper (Block 5) for coverage tracking
        """
        phase_techniques = self._build_phase_techniques()
        self._kill_chain.start()

        for phase in self.PHASES:
            techniques = phase_techniques.get(phase, [])
            if not techniques:
                self._kill_chain.advance()
                continue

            for technique in techniques:
                self._step_counter += 1
                step = technique.execute(self.context)
                step.step_number = self._step_counter
                step.phase       = phase.value

                self._kill_chain.record_step(step)
                yield step

            # Advance to next phase after all techniques in this phase run
            if not self._kill_chain.is_terminal:
                self._kill_chain.advance()

    @property
    def kill_chain_summary(self) -> dict:
        return self._kill_chain.summary()

    @property
    def mitre_techniques(self) -> list[str]:
        """Return all MITRE technique IDs this scenario uses."""
        phase_techniques = self._build_phase_techniques()
        ids = []
        for techs in phase_techniques.values():
            for t in techs:
                if t.TECHNIQUE_ID and t.TECHNIQUE_ID not in ids:
                    ids.append(t.TECHNIQUE_ID)
        return ids
