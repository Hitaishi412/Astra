# ASTRA — Integration & Bug Fixes

This patch set fixes 12 files. Drop them into your repo at the same paths.
Also: **delete `apply_seed_patch.py`** — it's a one-off migration that's already been applied.

---

## Critical fixes (caused real misbehaviour)

### 1. `core/scoring/calculator.py` — silent grade inflation
The six scoring weights in `config/settings.py` sum to **1.20**, not 1.0. The old code computed a weighted sum and clamped to 100. Result: a near-perfect 95-across-the-board session was reported as a perfect 100; a realistic 56 was reported as 67. Every score that's ever been recorded was inflated.

**Fix:** divide by the actual sum-of-weights so a perfect score is exactly 100.
**Bonus:** `_containment_score` now returns 0 for unknown phases instead of using `_MAX_PHASE_PENALTY` as a fallback (which was also wrong — it returned 0 anyway, but for the wrong reason).

### 2. `dashboard/callbacks/streaming.py` — sessions never actually launched
The launch button POSTed to `/attacks/run/{scenario}` with `json={"session_id": ..., "difficulty": ..., "stream": True}`. But the FastAPI endpoint expects those as **query parameters** (they're individual function args, not a Pydantic model). The body was ignored, so the API got `session_id=None` and the simulation started without a session ID — meaning no events ever reached the buffer for that session. **The "Launch" button was effectively broken.** Fixed by changing `json=` to `params=`.

Also fixed: `_SessionBuffer.subscriber_task` was annotated as `asyncio.Task` but stored a `threading.Thread` (the slot was deliberately mistyped per a comment, but it caused thread leaks because `disconnect()` never properly joined or cancelled). Now uses a proper `worker_thread` field with a stop event.

The abort callback was also incomplete: it called `_launcher_form()` with no args, but the current `_launcher_form` requires a `mode` dict. It now reads `active-mode` and rebuilds the right launcher.

### 3. `api/routers/attacks.py` — concurrent sessions clobber each other
A single module-level `_orchestrator = AttackOrchestrator()` was shared across **all** sessions. If two users ran scenarios simultaneously (or one user started a stepwise scenario while the dashboard streamed another), they overwrote each other's loaded scenario. Fixed: per-session orchestrator dict keyed by `session_id`, with proper cleanup on completion/abort.

Also: `/attacks/abort` previously took `session_id` as a query param, but the dashboard called it with `json={"session_id": ...}` — so it never worked. Now uses a proper Pydantic body.

### 4. `core/attack_engine/techniques/initial_access.py` — wrong MITRE ID on SpearphishingLink
Class was labelled "T1566.002 Spearphishing Link" in docstring but `TECHNIQUE_ID = "T1566.001"` (same as Attachment). This produced incorrect MITRE coverage data. Fixed to `T1566.002`.

### 5. `streaming/backend.py` — InMemoryBackend yielded wrong channel
When subscribed to multiple channels, the backend always yielded `channels[0]` regardless of which channel actually delivered the message. This made it impossible for in-memory consumers (used by tests and dashboard subscribers) to distinguish between log/alert/score streams. Fixed: queues now carry `(channel, message)` tuples.

### 6. `streaming/manager.py` — websocket cleanup bugs
- `disconnect()` never called `await ws.close()` — sockets leaked
- The consumer loop spawned `disconnect()` tasks while iterating the client snapshot; under `asyncio.Lock`, this could deadlock
- `shutdown()` didn't release the lock before awaiting `ws.close()` — same potential deadlock

Fixed by deferring close+cancel operations until outside the lock.

### 7. `core/detection_engine/rule_manager.py` — duplicate rule firings
`pipeline.initialize()` loads default rules twice — once from `rules/default/*.yml` on disk, once from the DB (where `db/seed.py` had also seeded the same rules). Both sets fired on every log, producing duplicate alerts and inflating the alert counts going into scoring.

Fixed: the rule manager now deduplicates by name (case-insensitive). Disk rules win since they load first.

### 8. `db/seed.py` — duplicate detection rules on every run
The seed function blindly inserted six default rules every time it ran, with no dedup check. Running `python -m db.seed` twice gave you 12 rules with the same names. Now idempotent: skips rules whose names already exist.

---

## Smaller fixes

### 9. `api/app.py` — duplicate router registration
The `attacks` router was registered in two identical `try/except ImportError` blocks. Removed the duplicate.

### 10. `api/routers/health.py` — `text` import below the function that uses it
Worked due to module-level resolution at call time, but ugly and breaks if the function is ever called during import. Moved imports to the top.

### 11. `core/log_engine/generator.py` and `noise.py` — global `_TEMPLATE_DIR` mutation
The `template_dir` constructor argument mutated the module-level global, meaning one generator's custom dir would poison every other generator. Custom dirs aren't actually used in production, but the API was unsafe. Now isolated to per-call.

### 12. **Delete `apply_seed_patch.py`**
This is a one-shot migration script that has already been applied to the repo (the patches it would make are present in `scripts/seed_demo_progress.py` and `api/routers/progress.py`). Keeping it around just invites someone to run it again on an already-patched repo and break things. **Recommend `rm apply_seed_patch.py`.**

---

## Things I noticed but did NOT change

- `core/reports/templates.py` imports `Literal` but never uses it (lint nit, not a bug)
- `core/reports/session_facts.py` defines `_HOSTNAME_HINT` and `extract_ips` but never uses them (dead code, harmless)
- `dashboard/callbacks/api.py: refresh_history` uses `/scoring/leaderboard` as a stand-in (per its own comment); a `/sessions/recent-with-scores` endpoint would be nicer, but it's a known shortcut, not a bug
- The `kill_chain_phases` enum has 6 phases but `dashboard/callbacks/streaming.py:_phase_to_index` maps to a 7-cell strip (with "Persistence" and "Lateral Movement" doubled-up onto neighboring cells). Cosmetic / minor — kept the existing mapping
- `config.yaml` advertises weights summing to 1.0 (`{0.30, 0.25, 0.15, 0.15, 0.15}`) but the live `config/settings.py` defaults sum to 1.20 (`{0.25, 0.20, 0.10, 0.10, 0.15, 0.20}`). The new normalization makes both work; you may want to align them at some point

---

## Testing

The existing test suite should still pass — I kept all public APIs unchanged (RuleManager, LogGenerator, NoiseGenerator, SessionScorer, ConnectionManager, InMemoryBackend, etc.). The two behavioural tweaks worth re-running:

- `tests/test_scoring/test_calculator.py` — the `test_perfect_score_near_100` assertion now actually has a chance of being satisfied (before, it was checking `> 50` which was way under what the broken code produced)
- `tests/test_streaming/test_pipeline.py` — the in-memory channel-routing fix means `test_consumer_only_receives_subscribed_streams` now actually tests what it claims to test

Run:
```
pytest tests/ -v
```

If anything breaks, ping me and I'll look.
