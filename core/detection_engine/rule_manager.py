"""
core/detection_engine/rule_manager.py
──────────────────────────────────────
Loads, caches, and manages Sigma detection rules from two sources:

  1. Default rules — YAML files shipped under core/detection_engine/rules/default/
  2. User rules    — Sigma rule rows from the detection_rules DB table (per session)

The manager parses each rule once and caches the SigmaRule objects.
The Detection Pipeline holds a single RuleManager instance per session.

Deduplication: when both disk and DB sources contain rules with the same
human-readable name (which happens because db/seed.py also seeds defaults),
only the first one wins. This prevents duplicate alerts firing for the
same Sigma rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from core.detection_engine.sigma_parser import SigmaRule, parse_sigma_rule
from db import crud


# ─── Disk locations ──────────────────────────────────────────────────────────
DEFAULT_RULES_DIR = Path(__file__).parent / "rules" / "default"
USER_RULES_DIR = Path(__file__).parent / "rules" / "user"


class RuleManager:
    """
    Holds the active set of detection rules for a session.

    Usage:
        mgr = RuleManager()
        mgr.load_defaults_from_disk()
        await mgr.load_user_rules_from_db(db_session, session_id="...")
        rules = mgr.active_rules()
    """

    def __init__(self):
        self._rules: dict[str, SigmaRule] = {}             # rule_id → SigmaRule
        self._rule_meta: dict[str, dict] = {}              # rule_id → metadata
        self._names_seen: set[str] = set()                 # case-insensitive names

    # ── Loading ──────────────────────────────────────────────────────────────
    def load_defaults_from_disk(self) -> int:
        """
        Walk DEFAULT_RULES_DIR and parse every .yml/.yaml file.
        Returns the number of rules loaded.
        """
        count = 0
        if not DEFAULT_RULES_DIR.exists():
            return 0

        for path in sorted(DEFAULT_RULES_DIR.glob("*.y*ml")):
            try:
                yaml_text = path.read_text(encoding="utf-8")
                rule = parse_sigma_rule(yaml_text, rule_id=path.stem)
                if self._is_dup_name(rule.name):
                    continue
                self._rules[rule.id] = rule
                self._rule_meta[rule.id] = {
                    "source": "default",
                    "path": str(path),
                    "enabled": True,
                }
                self._names_seen.add(rule.name.strip().lower())
                count += 1
            except Exception as e:
                # Don't fail the whole load over one bad file
                print(f"[RULE_MGR] Failed to parse {path.name}: {e}")
        return count

    async def load_user_rules_from_db(
        self,
        db: AsyncSession,
        session_id: Optional[str] = None,
    ) -> int:
        """
        Load rules from the detection_rules table.
        Includes default rules (is_default=True) and session-specific rules.
        """
        count = 0
        rules = await crud.get_active_rules(db, session_id=session_id)
        for rule_row in rules:
            try:
                parsed = parse_sigma_rule(rule_row.rule_yaml, rule_id=rule_row.id)
                # Override metadata from DB row
                parsed.name = rule_row.name
                parsed.description = rule_row.description or parsed.description
                parsed.severity = rule_row.severity or parsed.severity

                # Skip rules that already match a name we've loaded from disk.
                # This is the common case for "default" rules also seeded into the DB.
                if self._is_dup_name(parsed.name):
                    continue

                self._rules[parsed.id] = parsed
                self._rule_meta[parsed.id] = {
                    "source": "default" if rule_row.is_default else "user",
                    "db_id": rule_row.id,
                    "enabled": rule_row.enabled,
                }
                self._names_seen.add(parsed.name.strip().lower())
                count += 1
            except Exception as e:
                print(f"[RULE_MGR] Failed to parse DB rule {rule_row.name}: {e}")
        return count

    def add_rule_from_yaml(self, yaml_text: str, rule_id: Optional[str] = None) -> SigmaRule:
        """Parse and add a rule at runtime (e.g., from a user POST)."""
        rule = parse_sigma_rule(yaml_text, rule_id=rule_id)
        self._rules[rule.id] = rule
        self._rule_meta[rule.id] = {"source": "user", "enabled": True}
        self._names_seen.add(rule.name.strip().lower())
        return rule

    # ── Querying ─────────────────────────────────────────────────────────────
    def active_rules(self) -> list[SigmaRule]:
        """Return all currently enabled rules."""
        return [
            r for r_id, r in self._rules.items()
            if self._rule_meta.get(r_id, {}).get("enabled", True)
        ]

    def get_rule(self, rule_id: str) -> Optional[SigmaRule]:
        return self._rules.get(rule_id)

    def get_rule_metadata(self, rule_id: str) -> Optional[dict]:
        return self._rule_meta.get(rule_id)

    def all_rule_ids(self) -> list[str]:
        return list(self._rules.keys())

    # ── State management ─────────────────────────────────────────────────────
    def enable(self, rule_id: str) -> bool:
        if rule_id in self._rule_meta:
            self._rule_meta[rule_id]["enabled"] = True
            return True
        return False

    def disable(self, rule_id: str) -> bool:
        if rule_id in self._rule_meta:
            self._rule_meta[rule_id]["enabled"] = False
            return True
        return False

    def remove(self, rule_id: str) -> bool:
        if rule_id in self._rules:
            rule = self._rules[rule_id]
            del self._rules[rule_id]
            self._rule_meta.pop(rule_id, None)
            self._names_seen.discard(rule.name.strip().lower())
            return True
        return False

    def clear(self) -> None:
        self._rules.clear()
        self._rule_meta.clear()
        self._names_seen.clear()

    # ── Internal helpers ─────────────────────────────────────────────────────
    def _is_dup_name(self, name: str) -> bool:
        return (name or "").strip().lower() in self._names_seen

    # ── Stats ────────────────────────────────────────────────────────────────
    @property
    def stats(self) -> dict:
        return {
            "total_rules": len(self._rules),
            "active_rules": len(self.active_rules()),
            "default_rules": sum(
                1 for m in self._rule_meta.values() if m.get("source") == "default"
            ),
            "user_rules": sum(
                1 for m in self._rule_meta.values() if m.get("source") == "user"
            ),
        }

    def to_dict_list(self) -> list[dict]:
        """Serialize all rules for API responses."""
        return [
            {
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity,
                "technique_id": rule.technique_id,
                "tactic": rule.tactic,
                "source": self._rule_meta.get(rule.id, {}).get("source"),
                "enabled": self._rule_meta.get(rule.id, {}).get("enabled", True),
            }
            for rule in self._rules.values()
        ]
