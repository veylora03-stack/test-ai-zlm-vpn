# ERROR-PANEL

**Local-first Windows VPN profile management panel** — manage, validate, security-scan, test, rank and monitor VPN profiles imported from user-approved sources. Persian RTL dark-glass UI.

> **ERROR-PANEL is NOT a VPN client.** It manages and evaluates configurations.

---

## Features

- **Source Management** — Add GitHub/URL/manual sources; sync on demand
- **Multi-format Parser** — WireGuard, OpenVPN, VLess, VMess, Shadowsocks, Trojan
- **Deduplication** — SHA-256 fingerprint-based duplicate detection
- **Security Scanner** — 10 static checks, risk scoring (0-100), recommendations
- **Quarantine Flow** — Imported configs quarantined until user approves
- **Network Tester** — TCP connect latency with concurrency limiter (never port-scans)
- **Ranking Engine** — Composite score with adjustable weights
- **Analytics** — Protocol/status distribution charts, ping trend
- **Settings** — Adjustable ranking weights, test parameters, auto-refresh
- **Backup & Export** — SQLite backup, JSON/CSV export (local-only)
- **Audit Logs** — Every action logged and viewable

---

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Frontend   │────▶│   FastAPI    │────▶│   SQLite     │
│  Vanilla JS  │     │   Backend    │     │  (local DB)  │
│  RTL / Glass │     │  Python 3.11 │     │  aiosqlite   │
└──────────────┘     └──────────────┘     └──────────────┘
       │                     │
       │    ┌────────────────┤
       │    │    Services:   │
       │    │  • fetcher     │
       │    │  • parser      │
       │    │  • dedup       │
       │    │  • scanner     │
       │    │  • tester      │
       │    │  • ranker      │
       │    │  • audit       │
       │    └────────────────┘
```

**Security model:**
- Local-first: SQLite on disk, no telemetry
- No auto-connect: tester only does TCP connect, never establishes VPN tunnels
- No auto-execute: all actions require explicit user click
- Quarantine: unknown configs isolated until reviewed
- Fetch only user-approved sources
- Exports/backups never leave the local machine automatically

---

## Quick Start (Development)

```powershell
# Clone the repo
git clone https://github.com/veylora03-stack/ERROR-PANEL.git
cd ERROR-PANEL

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r backend/requirements.txt

# Delete old database (recommended for clean state)
Remove-Item backend\data\error.db -ErrorAction SilentlyContinue

# Start the backend (serves API + frontend)
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000

# Open browser
Start-Process "http://127.0.0.1:8000"
```

The backend serves the frontend static files at `/` and API at `/api/*`.

---

## Running Tests

All tests are offline-safe (no internet required):

```powershell
# Run individual phase tests
python scripts/test_phase2.py
python scripts/test_phase3.py
python scripts/test_phase4.py
python scripts/test_phase5.py
python scripts/test_phase6.py
python scripts/test_phase7.py
python scripts/test_phase8.py

# Syntax-check JS files
node --check frontend/js/api.js
node --check frontend/js/app.js
```

---

## Building the EXE

The EXE must be built on Windows by the user:

```powershell
# From the repo root
powershell -ExecutionPolicy Bypass -File scripts/build_exe.ps1
# Output: dist\ERROR.exe
```

Copy `dist\ERROR.exe` to any Windows machine and run it. It starts the server on `http://127.0.0.1:8000` and opens the browser automatically.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| CRUD | `/api/sources/` | Source management |
| CRUD | `/api/profiles/` | Profile management |
| POST | `/api/sources/{id}/sync` | Sync source |
| CRUD | `/api/quarantine/` | Quarantine management |
| POST | `/api/security/scan/{id}` | Security scan |
| POST | `/api/tests/run/{id}` | Run network test |
| GET/POST | `/api/metrics` | Metrics |
| GET | `/api/ranking/top` | Top profiles |
| GET | `/api/analytics/overview` | Analytics |
| GET/PATCH | `/api/settings` | Settings |
| GET | `/api/logs` | Audit logs |
| POST | `/api/backup` | Create backup |
| GET | `/api/export` | Export data |

---

## Phase History

| Phase | Title | Status |
|-------|-------|--------|
| P1 | Bootstrap and Specification | Done |
| P2 | Backend Core | Done |
| P3 | Frontend Shell | Done |
| P4 | Source Import and Quarantine | Done |
| P5 | Parser and Dedup | Done |
| P6 | Security Scanner | Done |
| P7 | Tester, Ranking, Analytics | Done |
| P8 | Settings, Backup, Packaging, Final | Done |

---

## License

MIT
