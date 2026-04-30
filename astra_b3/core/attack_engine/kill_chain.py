"""
core/attack_engine/kill_chain.py
─────────────────────────────────
Kill chain state machine.

Manages the ordered progression of attack phases based on the
Lockheed Martin Cyber Kill Chain (7 phases) and tracks:
  - Current phase
  - Which phases have been completed
  - Which steps have been executed in each phase
  - Whether the campaign has stalled / failed / succeeded

The orchestrator drives this machine forward one step at a time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from config.constants import KillChainPhase
from core.attack_engine.techniques.base import AttackStep


# ─── Phase metadata ───────────────────────────────────────────────────────────

@dataclass
class PhaseResult:
    """Tracks what happened in one kill chain phase."""
    phase:      KillChainPhase
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at:   Optional[datetime] = None
    steps:      list[AttackStep] = field(default_factory=list)
    success:    bool = False

    @property
    def duration_seconds(self) -> float:
        if self.ended_at is None:
            return 0.0
        return (self.ended_at - self.started_at).total_seconds()

    @property
    def step_count(self) -> int:
        return len(self.steps)

    @property
    def successful_steps(self) -> int:
        return sum(1 for s in self.steps if s.success)


# ─── Kill chain state machine ─────────────────────────────────────────────────

class KillChain:
    """
    State machine that tracks progression through attack phases.

    States:
        idle        → not started
        running     → actively executing a phase
        phase_done  → current phase complete, ready to advance
        complete    → all phases done (campaign succeeded)
        failed      → campaign stalled — no phase advanced for too long
        aborted     → manually stopped

    Usage:
        kc = KillChain(phases=[...])
        kc.start()
        while not kc.is_terminal:
            step = techniques[kc.current_phase].execute(ctx)
            kc.record_step(step)
            if kc.should_advance():
                kc.advance()
    """

    def __init__(self, phases: list[KillChainPhase]):
        if not phases:
            raise ValueError("Kill chain must have at least one phase.")
        self._phases    = phases
        self._phase_idx = 0
        self._state     = "idle"
        self._results:  list[PhaseResult] = []
        self._started_at: Optional[datetime] = None
        self._ended_at:   Optional[datetime] = None

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def current_phase(self) -> KillChainPhase:
        return self._phases[self._phase_idx]

    @property
    def current_result(self) -> Optional[PhaseResult]:
        return self._results[-1] if self._results else None

    @property
    def all_results(self) -> list[PhaseResult]:
        return list(self._results)

    @property
    def state(self) -> str:
        return self._state

    @property
    def is_terminal(self) -> bool:
        return self._state in ("complete", "failed", "aborted")

    @property
    def progress_pct(self) -> float:
        return round(self._phase_idx / len(self._phases) * 100, 1)

    @property
    def phases_completed(self) -> list[str]:
        return [r.phase.value for r in self._results if r.success]

    @property
    def all_steps(self) -> list[AttackStep]:
        steps = []
        for r in self._results:
            steps.extend(r.steps)
        return steps

    @property
    def total_steps(self) -> int:
        return sum(r.step_count for r in self._results)

    # ── State transitions ─────────────────────────────────────────────────────

    def start(self) -> None:
        if self._state != "idle":
            raise RuntimeError("Kill chain already started.")
        self._state      = "running"
        self._started_at = datetime.now(timezone.utc)
        self._results.append(PhaseResult(phase=self.current_phase))

    def record_step(self, step: AttackStep) -> None:
        """Record a completed technique step into the current phase."""
        if self._state != "running":
            raise RuntimeError(f"Cannot record step in state '{self._state}'.")
        if not self._results:
            raise RuntimeError("Kill chain not started.")
        self._results[-1].steps.append(step)

    def should_advance(self, min_successes: int = 1) -> bool:
        """
        Decide if the current phase has achieved enough success to advance.
        Default: advance after at least 1 successful step.
        """
        if not self.current_result:
            return False
        return self.current_result.successful_steps >= min_successes

    def advance(self) -> bool:
        """
        Move to the next phase.
        Returns True if advanced, False if already on the last phase (campaign complete).
        """
        if self._state != "running":
            return False

        # Close current phase
        current = self._results[-1]
        current.ended_at = datetime.now(timezone.utc)
        current.success  = current.successful_steps > 0

        self._phase_idx += 1

        if self._phase_idx >= len(self._phases):
            self._state    = "complete"
            self._ended_at = datetime.now(timezone.utc)
            return False   # no more phases

        # Open next phase
        self._results.append(PhaseResult(phase=self.current_phase))
        self._state = "running"
        return True

    def abort(self) -> None:
        self._state    = "aborted"
        self._ended_at = datetime.now(timezone.utc)
        if self._results and self._results[-1].ended_at is None:
            self._results[-1].ended_at = self._ended_at

    def fail(self) -> None:
        self._state    = "failed"
        self._ended_at = datetime.now(timezone.utc)

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        return {
            "state":            self._state,
            "phases_total":     len(self._phases),
            "phases_completed": len(self.phases_completed),
            "progress_pct":     self.progress_pct,
            "total_steps":      self.total_steps,
            "current_phase":    self.current_phase.value if not self.is_terminal else None,
            "phases_completed_list": self.phases_completed,
            "duration_seconds": (
                (self._ended_at or datetime.now(timezone.utc)) - self._started_at
            ).total_seconds() if self._started_at else 0,
        }
