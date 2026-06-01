# ASTRA — Adversary Simulation Platform

> A browser-based cyber range. Defend a live attack as the SOC analyst, or plan the intrusion as the operator — every scenario mapped to MITRE ATT&CK and scored.

### ▶ [Launch the live demo](https://astra-dashboard-qu4c.onrender.com) · [API docs](https://astra-api-mvc5.onrender.com/docs)

> ⏳ Hosted on Render's free tier — the first request after a period of inactivity may take ~30s while the service wakes.

![Python](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white)
![Dash](https://img.shields.io/badge/UI-Plotly%20Dash-3F4F75?logo=plotly&logoColor=white)
![Postgres](https://img.shields.io/badge/DB-Supabase%20Postgres-3ECF8E?logo=supabase&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What it is

ASTRA drops you into multi-stage attack scenarios and lets you experience them from **both sides of the keyboard**:

- **🛡 SOC Analyst (Blue Team)** — triage a live stream of logs and alerts as an attack unfolds in real time. Catch the kill chain before impact, mark true/false positives, and write up the incident. Scored on detection coverage, speed, and accuracy.
- **⚔ Pentester (Red Team)** — plan and execute a multi-phase intrusion against a defended target through a decision tree. Manage stealth, time, and lives; every move rolls against the blue team's defenses.
- **🟣 Purple Team** — *(coming soon)* run an attack, then switch hats and audit your own work as the defender.

It's built for SOC analysts, students, and career-changers who want realistic, repeatable practice — no homelab or paid course platform required.

> **Note on detection:** ASTRA's detection layer is **rule-based (Sigma-style) plus anomaly heuristics**, and scoring is performed by a deterministic, rule-based evaluator. It is a simulation/adversary-emulation environment, not an ML model.

---

## Features

- **Two training modes** (SOC defend / Pentester breach), with Purple Team planned.
- **Attack scenario library** — ransomware, APT espionage, insider threat, phishing chains, supply-chain compromise, and more.
- **MITRE ATT&CK scoring** — detection measured technique-by-technique against the ATT&CK matrix, surfaced as a coverage view, not a single opaque number.
- **Live event streaming** — logs, alerts, and score updates arrive in real time during a session (see *Streaming architecture* below).
- **Kill-chain progression** — every scenario maps to a 7-phase chain (Recon → Initial Access → Execution → Persistence → Lateral Movement → Exfiltration → Impact), tracked live.
- **Alert triage** — investigate alerts and classify them as true positive / false positive / escalate.
- **Report writer** — write the incident/engagement report when the session ends; a rule-based, five-dimension evaluator scores it and gives feedback.
- **Leaderboard** — every completed session ranked across users.

---

## Architecture

ASTRA runs as **two services** that share a database and a pub/sub bus:

```
        ┌─────────────────────┐         ┌──────────────────────┐
        │   astra-api          │         │   astra-dashboard     │
        │   FastAPI (async)    │         │   Plotly Dash         │
        │   - sessions/scoring │         │   - live SOC console  │
        │   - attack driver    │         │   - leaderboard/matrix│
        │   - publishes events │         │   - subscribes to     │
        └──────────┬───────────┘         └───────────┬──────────┘
                   │                                   │
        publish ▼  │                                   │  ▲ subscribe
            ┌──────┴───────────── Redis pub/sub ───────┴──────┐
            │        (Upstash in prod; in-memory locally)      │
            └──────────────────────────────────────────────────┘
                   │
        ┌──────────┴───────────┐
        │  Supabase Postgres    │  (RLS on all tables)
        └───────────────────────┘
```

### Tech stack

| Layer | Choice |
| --- | --- |
| API | FastAPI (async), Pydantic |
| ORM / DB driver | SQLAlchemy 2.0 (async) + asyncpg |
| Frontend | Plotly Dash, custom CSS (IBM Plex, terminal-brutalist theme) |
| Database | Supabase (PostgreSQL) with Row-Level Security; Supavisor transaction pooler |
| Auth | Firebase Authentication (email/password), verified server-side via firebase-admin |
| Streaming | Pluggable pub/sub backend — Redis (Upstash) in production, in-memory for local dev |
| Hosting | Render (two services) |
| Tests | pytest (360+ tests) |

### Streaming architecture

The streaming layer is built around a pluggable `get_backend()` factory (`streaming/backend.py`):

- **Local development** runs the API and dashboard in a single process, so an **in-memory** asyncio pub/sub works out of the box.
- **Production** runs them as two separate Render services. In-memory pub/sub can't cross a process boundary, so ASTRA switches to a **Redis** backend (set `REDIS_ENABLED=true` + `REDIS_URL`). Both processes connect to the same Redis instance, so events published by the API reach the dashboard's subscriber. The rest of the codebase is unchanged — only the backend implementation differs.

---

## Security

ASTRA is a security project, and the deployment is hardened accordingly:

- **Authentication** — Firebase email/password; ID tokens are minted client-side and **verified server-side** with firebase-admin. The authenticated identity is resolved from the token, never trusted from the request body.
- **IDOR remediation** — session-scoped endpoints across the `progress`, `scoring`, and `pentester` routers enforce **ownership checks**: a session that isn't yours returns **404** (not 403) to avoid disclosing whether an ID exists.
- **Row-Level Security** — RLS is enabled on **all** public Postgres tables. Supabase auto-exposes a PostgREST API over the database; RLS locks that surface down as defense-in-depth, so the data layer stays protected even if the application layer is bypassed.
- **Secrets hygiene** — all credentials (DB URL, Firebase service account, Redis URL) are supplied via environment variables, are gitignored, and are never committed.

---

## Project structure

```
api/              FastAPI app — routers, schemas, Firebase auth, dependencies
core/             simulation engines (attack driver, detection, scoring, pentester)
dashboard/        Plotly Dash UI — layouts, callbacks, components, assets (CSS/landing)
db/               async SQLAlchemy engine, models, CRUD helpers
streaming/        pub/sub backend abstraction (in-memory / Redis) + channel conventions
config/           settings loader (.env + config.yaml)
data/             log templates
reports/          report templates and generated output
scripts/          utility scripts
tests/            pytest suite
run.py            local entrypoint — runs API + dashboard in one process
run_dashboard.py  dashboard-only entrypoint (used by the production dashboard service)
config.yaml       non-secret defaults
requirements.txt  Python dependencies
```

---

## Getting started (local development)

### Prerequisites

- Python 3.11+
- A PostgreSQL database (a free [Supabase](https://supabase.com) project works well; SQLite is supported as a fallback for quick experiments)
- *(Optional)* a Firebase project for auth, and a Redis instance for cross-process streaming

### Setup

```bash
git clone https://github.com/aqueel707/Astra_integration.git
cd Astra_integration

python -m venv venv
source venv/bin/activate           # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # then edit .env (see below)
```

### Run

```bash
# Runs the API (:8000) and the dashboard (:8050) in a single process.
# In-memory streaming works in this mode — no Redis needed.
python run.py
```

Then open the dashboard at http://localhost:8050 and the API docs at http://localhost:8000/docs.

To mirror the production two-service topology locally, run them separately and set `REDIS_ENABLED=true` so events cross the process boundary:

```bash
python run.py            # API
python run_dashboard.py  # dashboard (separate terminal)
```

---

## Environment variables

Set these in `.env` for local development (and in your host's env-var UI for deployment):

| Variable | Required | Description |
| --- | --- | --- |
| `DATABASE_URL` | yes | Postgres connection string. In production, use Supabase's **transaction pooler** (port `6543`). |
| `DB_ECHO` | no | `true` to log SQL (default `false`). |
| `FIREBASE_ENABLED` | yes (prod) | `true` to enforce Firebase auth on the API. |
| `FIREBASE_PROJECT_ID` | if auth on | Your Firebase project ID. |
| `FIREBASE_SERVICE_ACCOUNT_B64` | if auth on | Base64-encoded service-account JSON (alternatively place the file at `secrets/firebase-admin.json`). |
| `REDIS_ENABLED` | prod | `true` to use the Redis streaming backend (required for live streaming across two services). |
| `REDIS_URL` | if redis on | `rediss://…` connection URL (e.g. Upstash). |
| `ASTRA_API_BASE` | dashboard | Public base URL of the API service (dashboard → API calls). |
| `ASTRA_DASHBOARD_PORT` | no | Dashboard port (defaults to `8050`). |

> **Connection pooling note:** ASTRA uses `NullPool` and connects through Supabase's Supavisor pooler. For the **transaction pooler** (`:6543`), asyncpg's prepared-statement cache is disabled (`statement_cache_size=0`) to stay compatible with transaction-level connection multiplexing.

---

## Deployment (Render)

ASTRA deploys as two Render services that share the database and Redis:

**`astra-api`**
- Start command: `python run.py --host 0.0.0.0 --port $PORT`
- Env: `DATABASE_URL`, `FIREBASE_ENABLED`, `FIREBASE_PROJECT_ID`, `FIREBASE_SERVICE_ACCOUNT_B64`, `REDIS_ENABLED=true`, `REDIS_URL`

**`astra-dashboard`**
- Start command: `ASTRA_DASHBOARD_PORT=$PORT python run_dashboard.py`
- Env: all of the above, plus `ASTRA_API_BASE` (the public URL of `astra-api`)

Both services must share the **same** `REDIS_URL` and have `REDIS_ENABLED=true` for live streaming to work — the API publishes and the dashboard subscribes through that shared Redis.

---

## Testing

```bash
pytest            # full suite
pytest -q         # quiet
pytest tests/...  # a specific module
```

---

## Roadmap

- [ ] **Purple Team mode** — run an attack, then audit your own detections as the defender.
- [ ] Cosmetic cleanup of live-session stat panels (a couple of legacy element IDs).
- [ ] Expanded scenario library.


## License

Released under the [MIT License](LICENSE).
