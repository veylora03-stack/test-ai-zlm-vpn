# ERROR-PANEL — Project Specification

## Name

ERROR-PANEL

## Goal

Local-first Windows panel to manage, validate, security-scan, test, rank and monitor VPN profiles imported from user-approved sources (GitHub raw files, direct URLs, manual entry). Persian RTL dark-glass UI. It is **NOT** a VPN client; it manages and evaluates configs.

---

## Principles

- **Local-first**: SQLite on disk, no telemetry, no external calls except user-approved source fetches.
- **Security by default**: Imported configs go to quarantine; nothing auto-connects or auto-executes.
- **User consent**: Sync/fetch only when the user clicks; sources only added by the user.
- **No scraping of unauthorized sites**: Only user-provided URLs; respect rate limits.
- **Transparency**: Audit log for every action.

---

## Stack

| Layer    | Technology                                                               |
|----------|--------------------------------------------------------------------------|
| Backend  | Python 3.11, FastAPI, SQLAlchemy 2 async, aiosqlite, httpx, pydantic v2, uvicorn |
| Frontend | Vanilla HTML/CSS/JS, no framework, Persian RTL, dark glassmorphism, static files, talks to backend via `fetch` at `http://127.0.0.1:8000` |
| Packaging| PyInstaller (later phase)                                                |

---

## Structure (repo root)

```
backend/
  app/
    main.py
    db.py
    models.py
    schemas.py
    api/
      sources.py
      profiles.py
      sync.py
      tests.py
      security.py
      analytics.py
      settings.py
    services/
      fetcher.py
      parser.py
      scanner.py
      tester.py
      ranker.py
      dedup.py
      audit.py
  data/
    error.db
frontend/
  index.html
  css/
    app.css
  js/
    app.js
    api.js
requirements.txt
README.md
LICENSE
.gitignore
PROJECT_SPEC.md
REPORT_PHASE_N.md files at root
```

---

## Database Schema

### `sources`

| Column           | Type                                                        | Notes                    |
|------------------|-------------------------------------------------------------|--------------------------|
| id               | INTEGER PK                                                  |                          |
| name             | TEXT                                                        |                          |
| type             | TEXT                                                        | `github` \| `url` \| `manual` |
| url              | TEXT                                                        |                          |
| status           | TEXT                                                        | `pending_review` \| `active` \| `paused` \| `suspicious` \| `blocked` |
| reputation_score | INTEGER                                                     | 0–100                    |
| last_sync_at     | DATETIME                                                    | nullable                 |
| last_error       | TEXT                                                        | nullable                 |
| notes            | TEXT                                                        | nullable                 |
| created_at       | DATETIME                                                    |                          |
| updated_at       | DATETIME                                                    |                          |

### `profiles`

| Column       | Type    | Notes                                                                          |
|--------------|---------|--------------------------------------------------------------------------------|
| id           | INTEGER PK |                                                                                |
| source_id    | INTEGER FK | → sources.id                                                                   |
| name         | TEXT    |                                                                                |
| protocol     | TEXT    | `wireguard` \| `openvpn` \| `vless` \| `vmess` \| `xray` \| `shadowsocks`      |
| server_host  | TEXT    |                                                                                |
| server_port  | INTEGER |                                                                                |
| country_code | TEXT    | ISO 3166-1 alpha-2                                                             |
| status       | TEXT    | `new` \| `quarantined` \| `pending_review` \| `approved` \| `tested` \| `failed` \| `blocked` \| `archived` |
| risk_score   | INTEGER | 0–100                                                                          |
| duplicate_of | INTEGER FK nullable | → profiles.id                                                           |
| config_ref   | TEXT    | Path or hash referencing the raw config file                                   |
| notes        | TEXT    | nullable                                                                       |
| created_at   | DATETIME|                                                                                |
| updated_at   | DATETIME|                                                                                |

### `metrics`

| Column         | Type    | Notes   |
|----------------|---------|---------|
| id             | INTEGER PK |       |
| profile_id     | INTEGER FK | → profiles.id |
| checked_at     | DATETIME |       |
| ping_ms        | REAL    | nullable |
| packet_loss_pct| REAL    | nullable |
| jitter_ms      | REAL    | nullable |
| download_mbps  | REAL    | nullable |
| upload_mbps    | REAL    | nullable |
| error_message  | TEXT    | nullable |

### `security_scans`

| Column        | Type    | Notes                                          |
|---------------|---------|-------------------------------------------------|
| id            | INTEGER PK |                                               |
| profile_id    | INTEGER FK | → profiles.id                                  |
| scanned_at    | DATETIME |                                                |
| risk_score    | INTEGER | 0–100                                          |
| risk_level    | TEXT    | `low` \| `medium` \| `high` \| `critical`       |
| warnings_json | TEXT    | JSON array of warning objects                   |
| recommendation| TEXT    | `approve` \| `review` \| `block`                |

### `audit_logs`

| Column       | Type    | Notes                  |
|--------------|---------|------------------------|
| id           | INTEGER PK |                       |
| created_at   | DATETIME |                        |
| action       | TEXT    | e.g. `import`, `approve`, `block` |
| entity_type  | TEXT    | e.g. `profile`, `source`        |
| entity_id    | INTEGER |                        |
| details_json | TEXT    | JSON object with extra info     |

---

## API (prefix `/api`)

### Health

| Method | Endpoint     | Description       |
|--------|-------------|-------------------|
| GET    | `/health`   | Health check      |

### Sources

| Method | Endpoint           | Description                     |
|--------|--------------------|---------------------------------|
| GET    | `/api/sources/`    | List all sources                |
| POST   | `/api/sources/`    | Add a new source                |
| GET    | `/api/sources/{id}`| Get source by ID                |
| PATCH  | `/api/sources/{id}`| Update source                   |
| DELETE | `/api/sources/{id}`| Delete source                   |
| POST   | `/api/sources/{id}/sync` | Trigger sync for a source |

### Profiles

| Method | Endpoint             | Description                                  |
|--------|----------------------|----------------------------------------------|
| GET    | `/api/profiles/`     | List profiles (filters: `status`, `protocol`, `search`) |
| POST   | `/api/profiles/`     | Add a profile                                |
| GET    | `/api/profiles/{id}` | Get profile by ID                            |
| PATCH  | `/api/profiles/{id}` | Update profile                               |
| DELETE | `/api/profiles/{id}` | Delete profile                               |

### Quarantine

| Method | Endpoint                          | Description               |
|--------|-----------------------------------|---------------------------|
| GET    | `/api/quarantine`                 | List quarantined profiles |
| POST   | `/api/quarantine/{id}/approve`    | Approve quarantined item  |
| POST   | `/api/quarantine/{id}/reject`     | Reject quarantined item   |
| POST   | `/api/quarantine/{id}/block`      | Block quarantined item    |

### Tests

| Method | Endpoint               | Description                    |
|--------|------------------------|--------------------------------|
| POST   | `/api/tests/run`       | Run connectivity/speed tests   |
| GET    | `/api/metrics?profile_id=` | Get metrics for a profile |

### Ranking

| Method | Endpoint                         | Description                                   |
|--------|----------------------------------|-----------------------------------------------|
| GET    | `/api/ranking/top?metric=`       | Top profiles by metric (`ping`, `download`, `upload`, `score`) |

### Analytics

| Method | Endpoint                | Description          |
|--------|-------------------------|----------------------|
| GET    | `/api/analytics/overview` | Analytics overview |

### Settings

| Method | Endpoint        | Description       |
|--------|-----------------|-------------------|
| GET    | `/api/settings/` | Get settings      |
| PATCH  | `/api/settings/` | Update settings   |

### Logs

| Method | Endpoint     | Description      |
|--------|-------------|------------------|
| GET    | `/api/logs`  | Get audit logs   |

---

## UI Pages

Single-page application with tabs, Persian labels, RTL layout, dark glassmorphism theme.

| Tab          | Content                                                        |
|--------------|----------------------------------------------------------------|
| Dashboard    | KPIs, top-3 lists                                              |
| Servers      | Table with search/filter/sort, detail drawer                   |
| Sources      | Add / sync / reputation display                                |
| Quarantine   | Approve / reject with warnings                                 |
| Analytics    | Charts                                                         |
| Settings     | Ranking weights, test limits, backup/export                    |
| Logs         | Audit log viewer                                               |

---

## Ranking Formula

Default weights (user-adjustable in Settings):

```
score = 0.35 * download_norm
      + 0.20 * upload_norm
      + 0.20 * ping_norm
      + 0.15 * stability_norm
      + 0.10 * security_norm
```

Normalization: each metric is min-max normalized across all tested profiles of the same protocol before weighting.

---

## Phases

| Phase | Title                                   | Description                                                    |
|-------|-----------------------------------------|----------------------------------------------------------------|
| P1    | Bootstrap and Specification             | Folder structure, spec, README, LICENSE, .gitignore, no code   |
| P2    | Backend Core                            | FastAPI app, DB setup, models, schemas, CRUD for sources/profiles |
| P3    | Frontend Shell                          | HTML skeleton, CSS glass theme, JS tab router, API client      |
| P4    | Source Import and Quarantine            | Fetcher service, source sync, quarantine flow                  |
| P5    | Parser and Dedup                        | Multi-protocol parser, dedup engine                            |
| P6    | Security Scanner                        | Risk scoring, warning generation, recommendation engine        |
| P7    | Tester, Ranking, Analytics              | Connectivity tests, ranking engine, analytics endpoints        |
| P8    | Settings, Backup, Packaging, Final      | Settings CRUD, DB backup/export, PyInstaller packaging, polish |
