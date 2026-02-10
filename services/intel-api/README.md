# Intel API — Executive Strategy Reporting (Daily / Weekly / Monthly)

This document explains the **Intel API “Strategy” module** that generates **executive-level cyber intelligence reports** from OpenCTI data. It covers what each component does, how the automation works, how to test each endpoint, and how to troubleshoot common issues.

> Target audience: engineers integrating OpenCTI + automation, and stakeholders who want “executive-grade” reporting rather than SOC-style IOC dumps.

---

## Table of Contents

- [Overview](#overview)
- [What You Get](#what-you-get)
- [Architecture & Data Flow](#architecture--data-flow)
- [Environment Variables](#environment-variables)
- [Endpoints & Testing](#endpoints--testing)
- [How Reports Are Built](#how-reports-are-built)
  - [Daily Executive Brief](#daily-executive-brief)
  - [Weekly Cyber Risk Brief](#weekly-cyber-risk-brief)
  - [Monthly Executive Cyber Risk Assessment](#monthly-executive-cyber-risk-assessment)
- [Key Executive Enhancements](#key-executive-enhancements)
- [Scheduling (Automation)](#scheduling-automation)
- [Code Map](#code-map)
- [Troubleshooting](#troubleshooting)
- [Customization Guide](#customization-guide)
- [Security Notes](#security-notes)

---

## Overview

The Intel API contains a `strategy/` module that generates **automated executive reports** inside OpenCTI as **Report objects**.

These reports summarize:
- **what happened** (high-level drivers),
- **so what** (business exposure / impact framing),
- **now what** (leadership actions),
- with technical details moved into a **Technical Annex** (so it doesn’t feel like a SOC-only artifact).

This is designed to support:
- leadership briefings (CISO / executives),
- strategic posture reviews,
- monthly risk summaries.

---

## What You Get

### 1) Daily Executive Cyber Brief
- Very short “Executive Snapshot”
- Key decisions list (auto-triage)
- Leadership actions
- Technical annex (minimal IOC list)

### 2) Weekly Executive Cyber Risk Brief
- Risk trajectory week-over-week
- Strategic drivers
- Rising/falling themes
- Exposure mapping (business domains)
- Top strategic risks

### 3) Monthly Executive Cyber Risk Assessment
- Most “executive-grade”
- Period-over-period trajectory
- Strategic drivers + exposure assessment
- Dominant activity clusters (noise reduced)
- Forward outlook (30–60 days)
- Technical annex (top risks + top observables)

---

## Architecture & Data Flow

### High-level pipeline

1. OpenCTI stores intelligence objects:
   - Reports (OSINT, connector imports, internal reports)
   - Observables created by enrichers (NLP/ML pipelines)

2. Intel API Strategy module queries OpenCTI GraphQL:
   - Fetches recent reports (by created_at)
   - Fetches recent observables (by created_at)

3. Strategy logic computes:
   - themes and trend deltas
   - risk scoring and triage labels
   - executive narrative sections (drivers, exposure, outlook)
   - lightweight clustering to reduce noise

4. Strategy writes back into OpenCTI:
   - Creates a new OpenCTI Report object
   - The report body contains all executive sections + annex

---

## Environment Variables

The `intel-api` container requires these variables:

### OpenCTI Connectivity
- `OPENCTI_BASE`  
  Example: `http://opencti:8080`

- `OPENCTI_TOKEN`  
  OpenCTI token used to authenticate GraphQL requests.

### Strategy Configuration
- `STRATEGY_ENABLED`  
  `true` to enable scheduler, otherwise strategy scheduler is disabled.

- `STRATEGY_TIMEZONE`  
  Example: `Asia/Karachi`

- `STRATEGY_CONFIG`  
  Path to config file (default: `/app/strategy/config.yml`)

### Schedules (cron format: `min hour dom mon dow`)
- `STRATEGY_DAILY_CRON`  
  Default: `0 9 * * *`

- `STRATEGY_WEEKLY_CRON`  
  Default: `0 9 * * 1` (Mondays)

- `STRATEGY_MONTHLY_CRON`  
  Default: `0 9 1 * *` (1st day of the month)

---

## Endpoints & Testing

### 1) Confirm API is live
```bash
curl http://localhost:8000/docs
````

### 2) Run Daily Report (manual trigger)

```bash
curl -X POST http://localhost:8000/strategy/run-daily
```

Expected output:

* JSON with created report id + report name

### 3) Run Weekly Report (manual trigger)

```bash
curl -X POST http://localhost:8000/strategy/run-weekly
```

### 4) Run Monthly Report (manual trigger)

```bash
curl -X POST http://localhost:8000/strategy/run-monthly
```

### 5) Validate the report in OpenCTI UI

* Open OpenCTI → **Analyses → Reports**
* Find:

  * `Executive Daily Cyber Brief — YYYY-MM-DD`
  * `Executive Weekly Cyber Risk Brief — Week ending YYYY-MM-DD`
  * `Executive Cyber Risk Assessment — Month YYYY`

---

## How Reports Are Built

All report generation happens in:

* `strategy/aggregator.py`

Data is pulled using:

* `strategy/opencti_client.py`

Risk scoring and triage label logic happens in:

* `strategy/scoring.py`

Scheduling is handled by:

* `strategy/scheduler.py`

---

### Daily Executive Brief

**Primary design goal:**
Make it “leadership readable” in 1 minute.

**Sections:**

* Executive Snapshot

  * risk posture: BASELINE / ATTENTION / ELEVATED
  * volume: reports + observables
  * top drivers (top 3 themes)

* Key Decisions (Auto-triage)

  * shows 6–8 top items with decision label
  * decisions come from risk score thresholds

* Leadership Actions

  * short, actionable, non-technical guidance

* Technical Annex

  * brief themes + a small IOC list (not the main story)

---

### Weekly Cyber Risk Brief

**Primary design goal:**
Show week-over-week posture and where leadership should focus.

**Adds:**

* Risk trajectory: **ELEVATED / STABLE / IMPROVING**
  derived from average risk delta + volume delta

* Strategic Drivers
  narrative interpretation of top themes

* Trend Signals (WoW)
  rising and falling themes

* Business Exposure Assessment
  mapping themes to business domains:

  * “Identity & Access”
  * “Internet-facing infrastructure”
  * “Third-party risk”
    etc.

---

### Monthly Executive Cyber Risk Assessment

**Primary design goal:**
Board / leadership review format.

**Adds:**

* Dominant Activity Clusters (“Noise reduced”)
  Uses lightweight similarity clustering to group related reports.

* Forward Outlook (Next 30–60 days)
  Derived from dominant themes using outlook templates.

* Technical annex kept at bottom.

---

## Key Executive Enhancements

These changes are what make reports feel executive-level:

### 1) “So what” narrative templates

Themes like `exploit`, `credential`, `supply chain` are converted into strategic meaning.

Example:

* `credential` → “leading indicator for account takeover and lateral movement risk.”

### 2) Exposure mapping

Themes are mapped to business exposure areas:

* phishing/credential → Identity & Access
* exploit/zero-day → Internet-facing infrastructure
* supply chain → Vendor/Third-party risk

### 3) Risk trajectory (directional posture)

Executives don’t want raw numbers; they want:

* **ELEVATED (↑)**
* **STABLE (→)**
* **IMPROVING (↓)**

### 4) Clustering for “Noise reduced”

Instead of dumping 100+ items, the system groups reports into a few “dominant clusters” with keywords.

---

## Scheduling (Automation)

The scheduler runs in the background inside `intel-api`:

* Daily report runs on `STRATEGY_DAILY_CRON`
* Weekly report runs on `STRATEGY_WEEKLY_CRON`
* Monthly report runs on `STRATEGY_MONTHLY_CRON`

**Manual triggers are always available** via API endpoints.

---

## Code Map

### `strategy/opencti_client.py`

* Responsible for:

  * GraphQL requests
  * list_reports()
  * list_observables()
  * create_report()

Important:

* For OpenCTI 6.9.15, do **NOT** query `confidence` on `stixCyberObservables`.

### `strategy/aggregator.py`

* Responsible for:

  * fetching data via OpenCTIClient
  * computing themes and trends
  * computing clusters
  * generating report markdown body

### `strategy/scoring.py`

* Responsible for:

  * risk score calculation (0–100)
  * decision label mapping (BLOCK / MONITOR / IGNORE)
  * uses config thresholds and org profile weights

### `strategy/scheduler.py`

* Responsible for:

  * APScheduler CronTrigger jobs
  * run_daily / run_weekly / run_monthly wrappers
  * scheduling based on env cron strings

### `app.py`

* Exposes:

  * `/strategy/run-daily`
  * `/strategy/run-weekly`
  * `/strategy/run-monthly`
* Starts the scheduler at application startup.

---

## Troubleshooting

### A) Monthly endpoint returns 404 Not Found

Cause:

* `app.py` does not define the route or router prefix is different.

Fix:

* Confirm `@router.post("/run-monthly")` exists
* Confirm router is included: `app.include_router(router)`
* Use the correct URL:
  `POST /strategy/run-monthly`

---

### B) Internal Server Error with GraphQL schema validation

Symptom:

* Error like:
  `Cannot query field "confidence" on type "StixCyberObservable".`

Cause:

* Query includes a field not supported by your OpenCTI version.

Fix:

* Remove invalid fields from query inside `list_observables()`.

---

### C) intel-api container exits (ImportError: partially initialized module)

Cause:

* Circular imports (e.g., opencti_client importing aggregator while aggregator imports opencti_client)

Fix:

* Ensure `opencti_client.py` does NOT import `aggregator.py` (or anything that imports it).

---

### D) Token issues / 401/403

Fix checklist:

* `OPENCTI_TOKEN` exists in container env
* Token is correct in OpenCTI
* `OPENCTI_BASE` is reachable from container (usually `http://opencti:8080`)

Test inside container:

```bash
docker compose exec intel-api sh -lc 'python - <<PY
import os,requests
base=os.getenv("OPENCTI_BASE","http://opencti:8080").rstrip("/")
tok=os.getenv("OPENCTI_TOKEN","")
r=requests.post(base+"/graphql",
  headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"},
  json={"query":"query{about{version}}"},
  timeout=15
)
print(r.status_code, r.text[:200])
PY'
```

---

## Customization Guide

### 1) Change executive narrative

Edit templates in `strategy/aggregator.py`:

* `THEME_INTERPRETATION`
* `THEME_TO_EXPOSURE`
* `leadership_actions_from_themes()`
* `Forward Outlook` rules in monthly builder

### 2) Reduce/Increase technical annex content

* Daily: adjust `top_obs = observables[:3]`
* Monthly: adjust `top_obs = observables[:10]`

### 3) Triage thresholds (BLOCK/MONITOR/IGNORE)

Adjust config thresholds in:

* `strategy/config.yml`
  and logic in:
* `strategy/scoring.py`

---

## Security Notes

* Treat `OPENCTI_TOKEN` as a secret.
* Do not expose Intel API publicly without auth.
* If exposed, place behind a reverse proxy with:

  * authentication
  * TLS
  * IP allowlists

---

## Quick Test Checklist

1. Container up:

```bash
docker compose ps | grep intel-api
```

2. Docs visible:

```bash
curl http://localhost:8000/docs
```

3. Run daily:

```bash
curl -X POST http://localhost:8000/strategy/run-daily
```

4. Run weekly:

```bash
curl -X POST http://localhost:8000/strategy/run-weekly
```

5. Run monthly:

```bash
curl -X POST http://localhost:8000/strategy/run-monthly
```

6. Confirm in OpenCTI UI:

* Analyses → Reports → look for report title.

---

