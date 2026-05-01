"""
core/detection_engine/sigma_parser.py
──────────────────────────────────────
Sigma rule parser and evaluator.

This is a *minimal* Sigma implementation tailored for ASTRA's training scope.
We don't aim for full Sigma spec compliance — we support the subset that
matters for cybersecurity training:
  - Direct field matches:        field: value
  - Multiple values (OR):        field: [v1, v2, v3]
  - Contains modifier:           field|contains: 'substring'
  - Greater-than modifier:       field|gt: 100
  - Count aggregations:          condition: selection | count() > N
  - Timeframe aggregations:      timeframe: 5m
  - And/Or composition:          condition: selection1 and selection2

For full Sigma spec, swap this for the official `pysigma` package later —
the public interface (parse, evaluate) will stay the same.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

import yaml

from core.log_engine.schemas import LogEntry


# ─── Parsed rule data structure ──────────────────────────────────────────────
@dataclass
class SigmaRule:
    """A parsed, ready-to-evaluate Sigma rule."""
    id: str
    name: str
    description: str
    severity: str
    technique_id: Optional[str] = None
    tactic: Optional[str] = None

    # Detection logic
    selections: dict[str, dict] = field(default_factory=dict)  # name -> conditions
    condition: str = "selection"
    timeframe_seconds: Optional[int] = None
    aggregation: Optional[dict] = None  # {'op': 'count', 'field': ..., 'op_compare': '>', 'value': N}

    # Source filter (only evaluate against matching log sources)
    log_source_category: Optional[str] = None
    log_source_product: Optional[str] = None


# ─── Public parsing entry point ─────────────────────────────────────────────
def parse_sigma_rule(yaml_text: str, rule_id: Optional[str] = None) -> SigmaRule:
    """
    Parse a YAML Sigma rule string into a SigmaRule.
    Raises ValueError on invalid structure.
    """
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}")

    if not isinstance(data, dict):
        raise ValueError("Sigma rule root must be a YAML mapping.")

    detection = data.get("detection", {})
    if not isinstance(detection, dict):
        raise ValueError("Sigma rule must have a 'detection' block.")

    # Pull selections (everything under detection except 'condition' and 'timeframe')
    selections = {
        k: v for k, v in detection.items()
        if k not in ("condition", "timeframe") and isinstance(v, dict)
    }

    if not selections:
        raise ValueError("Sigma rule must have at least one selection block.")

    # Parse condition
    raw_condition = detection.get("condition", "selection")
    aggregation = _parse_aggregation(raw_condition)

    # Parse timeframe (e.g. "5m", "1h")
    timeframe_seconds = _parse_timeframe(detection.get("timeframe"))

    # Tags → MITRE
    technique_id = None
    tactic = None
    for tag in data.get("tags", []) or []:
        tag_lower = tag.lower()
        # Technique tags look like "attack.t1059" or "attack.t1059.001"
        if tag_lower.startswith("attack.t") and len(tag_lower) > len("attack.t"):
            # Strip "attack." prefix → "t1059.001" → "T1059.001"
            technique_id = tag[len("attack."):].upper()
        # Tactic tags look like "attack.execution", "attack.lateral_movement"
        elif tag_lower.startswith("attack."):
            tactic = tag[len("attack."):].lower()

    log_source = data.get("logsource", {}) or {}

    return SigmaRule(
        id=rule_id or data.get("id") or data.get("title", "unnamed"),
        name=data.get("title", "Untitled Rule"),
        description=data.get("description", ""),
        severity=(data.get("level", "medium")).lower(),
        technique_id=technique_id,
        tactic=tactic,
        selections=selections,
        condition=raw_condition,
        timeframe_seconds=timeframe_seconds,
        aggregation=aggregation,
        log_source_category=log_source.get("category"),
        log_source_product=log_source.get("product"),
    )


# ─── Public evaluation entry point ──────────────────────────────────────────
def evaluate_rule(rule: SigmaRule, logs: list[LogEntry]) -> list[list[LogEntry]]:
    """
    Evaluate a parsed Sigma rule against a batch of logs.

    Returns a list of "matches", where each match is a list of LogEntry objects
    that together caused the rule to fire. For simple rules, each match is one
    log. For aggregation rules (count > N), each match is the group of logs
    that together exceeded the threshold.
    """
    # 1. Pre-filter by log source if specified
    candidate_logs = _filter_by_log_source(logs, rule)
    if not candidate_logs:
        return []

    # 2. Find logs that match each selection
    selection_matches: dict[str, list[LogEntry]] = {}
    for name, conditions in rule.selections.items():
        selection_matches[name] = [
            log for log in candidate_logs if _log_matches_selection(log, conditions)
        ]

    # 3. Combine selections per the condition expression
    matched_logs = _evaluate_condition(rule.condition, selection_matches)

    if not matched_logs:
        return []

    # 4. If there's an aggregation (count > N), group and threshold
    if rule.aggregation:
        return _apply_aggregation(matched_logs, rule)

    # 5. Otherwise, each matched log is its own match
    return [[log] for log in matched_logs]


# ════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ════════════════════════════════════════════════════════════════════════════

# ─── Condition parsing ──────────────────────────────────────────────────────
_AGG_PATTERN = re.compile(
    r"(?P<sel>\w+)\s*\|\s*count\s*\((?P<field>[^)]*)\)\s*(?P<op>[<>=!]+)\s*(?P<value>\d+)",
    re.IGNORECASE,
)


def _parse_aggregation(condition: str) -> Optional[dict]:
    """
    Parse 'selection | count(field) > N' into a structured form.
    Returns None if the condition has no aggregation.
    """
    m = _AGG_PATTERN.search(condition or "")
    if not m:
        return None
    return {
        "selection": m.group("sel"),
        "group_by_field": m.group("field").strip() or None,
        "op": m.group("op"),
        "value": int(m.group("value")),
    }


_TIMEFRAME_PATTERN = re.compile(r"^(\d+)([smhd])$")


def _parse_timeframe(tf: Optional[str]) -> Optional[int]:
    """Parse '5m', '1h', '30s', '1d' into seconds."""
    if not tf or not isinstance(tf, str):
        return None
    m = _TIMEFRAME_PATTERN.match(tf.strip())
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2)
    return {"s": n, "m": n * 60, "h": n * 3600, "d": n * 86400}[unit]


# ─── Log source filtering ───────────────────────────────────────────────────
def _filter_by_log_source(logs: list[LogEntry], rule: SigmaRule) -> list[LogEntry]:
    """Filter logs to only those matching the rule's logsource block."""
    cat = rule.log_source_category
    prod = rule.log_source_product

    if not cat and not prod:
        return logs

    result = []
    for log in logs:
        if cat and log.category and cat != log.category:
            # Allow partial match for category (e.g., 'process_creation' matches 'process_creation_event')
            if cat not in log.category:
                continue
        if prod:
            # Map product → log source
            if prod == "windows" and log.source != "windows_event":
                continue
            if prod == "linux" and log.source != "linux_syslog":
                continue
        result.append(log)
    return result


# ─── Selection matching ─────────────────────────────────────────────────────
def _log_matches_selection(log: LogEntry, conditions: dict[str, Any]) -> bool:
    """
    A selection is a dict of conditions. ALL conditions must match (AND).
    Handles modifiers like field|contains, field|gt.
    """
    for key, expected in conditions.items():
        # Parse modifiers: 'process_name|contains' -> ('process_name', 'contains')
        if "|" in key:
            field_name, modifier = key.split("|", 1)
        else:
            field_name, modifier = key, "equals"

        actual = _get_log_field(log, field_name)

        if not _check_condition(actual, expected, modifier):
            return False
    return True


def _get_log_field(log: LogEntry, field_name: str) -> Any:
    """Look up a field on the log, falling back to raw_data."""
    if hasattr(log, field_name):
        return getattr(log, field_name)
    return log.raw_data.get(field_name)


def _check_condition(actual: Any, expected: Any, modifier: str) -> bool:
    """Apply a single condition with its modifier."""
    if actual is None:
        return False

    # Normalize expected to a list for uniform handling
    expected_list = expected if isinstance(expected, list) else [expected]

    if modifier == "equals":
        return any(_eq(actual, e) for e in expected_list)
    if modifier == "contains":
        return any(_contains(actual, e) for e in expected_list)
    if modifier in ("gt", "greater"):
        return any(_gt(actual, e) for e in expected_list)
    if modifier in ("lt", "less"):
        return any(_lt(actual, e) for e in expected_list)
    if modifier == "startswith":
        return any(isinstance(actual, str) and actual.lower().startswith(str(e).lower()) for e in expected_list)
    if modifier == "endswith":
        return any(isinstance(actual, str) and actual.lower().endswith(str(e).lower()) for e in expected_list)

    # Unknown modifier → fall back to equals
    return any(_eq(actual, e) for e in expected_list)


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    return a == b


def _contains(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return b.lower() in a.lower()
    return False


def _gt(a: Any, b: Any) -> bool:
    try:
        return float(a) > float(b)
    except (TypeError, ValueError):
        return False


def _lt(a: Any, b: Any) -> bool:
    try:
        return float(a) < float(b)
    except (TypeError, ValueError):
        return False


# ─── Condition expression evaluation ────────────────────────────────────────
def _evaluate_condition(
    condition: str,
    selection_matches: dict[str, list[LogEntry]],
) -> list[LogEntry]:
    """
    Combine selection results per the condition expression.

    Supported forms:
        "selection"                   → just return that selection's matches
        "sel1 and sel2"              → logs matching both
        "sel1 or sel2"               → logs matching either
        "sel | count(...) > N"       → return all matched logs (aggregation handled later)

    For unsupported expressions, default to the first selection.
    """
    # Strip aggregation suffix; the matched logs are still the selection's
    cond = re.sub(r"\|\s*count.*$", "", condition or "selection").strip()

    # Just a single selection name
    if cond in selection_matches:
        return selection_matches[cond]

    # AND
    if " and " in cond:
        parts = [p.strip() for p in cond.split(" and ")]
        sets = [set(selection_matches.get(p, [])) for p in parts]
        if not sets:
            return []
        common = sets[0]
        for s in sets[1:]:
            common &= s
        return list(common)

    # OR
    if " or " in cond:
        parts = [p.strip() for p in cond.split(" or ")]
        result = []
        seen = set()
        for p in parts:
            for log in selection_matches.get(p, []):
                if log.id not in seen:
                    seen.add(log.id)
                    result.append(log)
        return result

    # Fallback: first selection
    return next(iter(selection_matches.values()), [])


# ─── Aggregation handling (count() > N within timeframe) ────────────────────
def _apply_aggregation(
    matched_logs: list[LogEntry],
    rule: SigmaRule,
) -> list[list[LogEntry]]:
    """
    Group matched logs by the aggregation field and apply the count threshold.
    If a timeframe is specified, only consider logs within rolling windows.
    """
    agg = rule.aggregation
    if not agg:
        return [[log] for log in matched_logs]

    group_field = agg["group_by_field"]
    threshold = agg["value"]
    op = agg["op"]
    tf_seconds = rule.timeframe_seconds

    # Group logs by the field (or all into one bucket if no field)
    groups: dict[Any, list[LogEntry]] = defaultdict(list)
    for log in matched_logs:
        if group_field:
            key = _get_log_field(log, group_field) or "__none__"
        else:
            key = "__all__"
        groups[key].append(log)

    matches = []
    for key, group_logs in groups.items():
        group_logs.sort(key=lambda x: x.timestamp)

        if tf_seconds:
            # Rolling time window: any window of tf_seconds with enough logs?
            window_match = _check_time_window(group_logs, tf_seconds, threshold, op)
            if window_match:
                matches.append(window_match)
        else:
            # No timeframe: just count total
            if _compare_count(len(group_logs), op, threshold):
                matches.append(group_logs)

    return matches


def _check_time_window(
    logs: list[LogEntry],
    window_seconds: int,
    threshold: int,
    op: str,
) -> Optional[list[LogEntry]]:
    """
    Sliding window: return the first window of `window_seconds` containing
    enough logs to satisfy `op threshold`. Returns None if no such window.
    """
    if not logs:
        return None
    delta = timedelta(seconds=window_seconds)
    n = len(logs)
    left = 0
    for right in range(n):
        while logs[right].timestamp - logs[left].timestamp > delta:
            left += 1
        count = right - left + 1
        if _compare_count(count, op, threshold):
            return logs[left:right + 1]
    return None


def _compare_count(count: int, op: str, threshold: int) -> bool:
    """Compare a count against threshold using the operator."""
    if op == ">":
        return count > threshold
    if op == ">=":
        return count >= threshold
    if op == "<":
        return count < threshold
    if op == "<=":
        return count <= threshold
    if op in ("==", "="):
        return count == threshold
    return False
