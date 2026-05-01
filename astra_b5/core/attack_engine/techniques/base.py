"""
core/attack_engine/techniques/base.py
──────────────────────────────────────
Abstract base class for every attack technique in the engine.

A "technique" maps 1-to-1 with a MITRE ATT&CK technique ID (e.g. T1566.001).
Each technique knows:
  - Which kill chain phase it belongs to
  - Its MITRE metadata (ID, name, tactic)
  - How to produce a structured AttackStep output
  - How difficulty scales its behaviour

Subclasses only need to implement `execute()` and fill in class-level metadata.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
import random
import uuid

from config.constants import KillChainPhase, Severity, Difficulty


# ─── Output data structure ────────────────────────────────────────────────────

@dataclass
class AttackStep:
    """
    The single output unit from any technique execution.
    This is what the Log Engine (Block 3) and MITRE Mapper (Block 5) consume.
    Every field here maps directly to an AttackEvent DB row.
    """
    # Identity
    id:               str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:        datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Kill chain position
    phase:            str = ""           # KillChainPhase value
    step_number:      int = 0

    # MITRE
    technique_id:     str = ""           # e.g. "T1566.001"
    technique_name:   str = ""           # e.g. "Phishing: Spearphishing Attachment"
    tactic:           str = ""           # e.g. "initial_access"

    # What happened
    description:      str = ""           # Human-readable narrative of the step
    source_host:      Optional[str] = None
    target_host:      Optional[str] = None
    success:          bool = True
    severity:         str = "medium"

    # Arbitrary payload the log engine uses to build realistic logs
    extra_data:       dict[str, Any] = field(default_factory=dict)

    # Noise hints: how many log entries should Block 3 generate from this step?
    log_count_hint:   int = 5            # Baseline
    noise_count_hint: int = 10           # Benign noise to mix in


# ─── Base technique ───────────────────────────────────────────────────────────

class BaseTechnique(ABC):
    """
    Abstract base class for all ATT&CK techniques.

    Subclass contract:
        TECHNIQUE_ID   = "T1566.001"
        TECHNIQUE_NAME = "Phishing: Spearphishing Attachment"
        TACTIC         = "initial_access"
        PHASE          = KillChainPhase.DELIVERY
        BASE_SEVERITY  = Severity.HIGH

    Then implement: execute(context) -> AttackStep
    """

    # ── Subclasses fill these in ──────────────────────────────────────────────
    TECHNIQUE_ID:   str = ""
    TECHNIQUE_NAME: str = ""
    TACTIC:         str = ""
    PHASE:          KillChainPhase = KillChainPhase.DELIVERY
    BASE_SEVERITY:  Severity = Severity.MEDIUM

    def __init__(self, difficulty: str = Difficulty.MEDIUM):
        self.difficulty = difficulty

    # ── Helpers available to all subclasses ──────────────────────────────────

    @staticmethod
    def _fake_ip(internal: bool = False) -> str:
        if internal:
            return f"10.0.{random.randint(1, 10)}.{random.randint(2, 254)}"
        return f"{random.randint(50, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(2, 254)}"

    @staticmethod
    def _fake_hostname(prefix: str = "DESKTOP") -> str:
        suffix = "".join(random.choices("ABCDEFGHJKLMNPQRSTVWXYZ0123456789", k=5))
        return f"{prefix}-{suffix}"

    @staticmethod
    def _fake_username() -> str:
        names = [
            "jsmith", "amartinez", "bwilson", "lnguyen", "mgarcia",
            "tcook", "rlee", "sjohnson", "kpatel", "dthompson",
        ]
        return random.choice(names)

    def _success_rate(self) -> float:
        """Higher difficulty = attacker is better = higher success rate."""
        rates = {
            Difficulty.BEGINNER: 0.60,
            Difficulty.MEDIUM:   0.75,
            Difficulty.HARD:     0.88,
            Difficulty.EXPERT:   0.96,
        }
        return rates.get(self.difficulty, 0.75)

    def _did_succeed(self) -> bool:
        return random.random() < self._success_rate()

    def _log_count(self, base: int = 5) -> int:
        """
        Expert attackers leave fewer logs (evasion).
        Beginners are noisy.
        """
        multipliers = {
            Difficulty.BEGINNER: 3.0,
            Difficulty.MEDIUM:   2.0,
            Difficulty.HARD:     1.2,
            Difficulty.EXPERT:   0.6,
        }
        m = multipliers.get(self.difficulty, 2.0)
        return max(1, int(base * m * random.uniform(0.7, 1.3)))

    def _make_step(self, **overrides) -> AttackStep:
        """Build an AttackStep pre-filled with this technique's metadata."""
        base = dict(
            phase          = self.PHASE.value,
            technique_id   = self.TECHNIQUE_ID,
            technique_name = self.TECHNIQUE_NAME,
            tactic         = self.TACTIC,
            severity       = self.BASE_SEVERITY.value,
            log_count_hint = self._log_count(),
            noise_count_hint = self._log_count(base=10),
        )
        base.update(overrides)
        return AttackStep(**base)

    # ── Subclasses implement this ─────────────────────────────────────────────

    @abstractmethod
    def execute(self, context: dict[str, Any]) -> AttackStep:
        """
        Simulate one execution of this technique.

        Args:
            context: shared campaign context (target IPs, usernames, prior steps, etc.)

        Returns:
            AttackStep: structured output consumed by the Log Engine.
        """
        ...
