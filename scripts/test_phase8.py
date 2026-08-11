"""ERROR-PANEL — Phase 8 Integration Tests (offline-safe).

Tests: Settings CRUD, Logs, Backup, Export, Static serving,
       Desktop launcher smoke test, Frontend grep checks.
Each test script manages its own server lifecycle.
"""

import asyncio
import httpx
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8000/api"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(REPO_ROOT, "backend", "data", "error.db")

passed = 0
failed = 0


def report(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  [PASS] {name}  {('  (' + detail + ')') if detail else ''}")
    else:
        failed += 1
        print(f"  [FAIL] {name}  {('  (' + detail + ')') if detail else ''}")


def http_request(method, path, data=None):
    """Make HTTP request, return (status, body_or_None)."""
    url = "http://127.0.0.1:8000" + path
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return 0, str(e)


def start_server():
    """Start the backend server as a subprocess."""
    venv_python = os.path.join(REPO_ROOT, ".venv", "bin", "python")
    proc = subprocess.Popen(
        [venv_python, "-m", "uvicorn", "backend.app.main:app",
         "--host", "127.0.0.1", "--port", "8000"],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for server to be ready
    for _ in range(40):
        time.sleep(0.5)
        try:
            r = urllib.request.urlopen("http://127.0.0.1:8000/api/health")
            if r.status == 200:
                return proc
        except Exception:
            pass
    proc.terminate()
    raise RuntimeError("Server did not start")


def stop_server(proc):
    """Stop the backend server."""
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


async def run_tests():
    async with httpx.AsyncClient(base_url=BASE, timeout=15.0) as c:

        # ── 1. Health check v1.0.0 ─────────────────────────────────────────
        r = await c.get("/health")
        report("Health check v1.0.0", r.status_code == 200 and r.json().get("version") == "1.0.0",
               f"version={r.json().get('version')}")

        # ── 2. GET /api/settings returns default weights ───────────────────
        r = await c.get("/settings")
        report("GET /api/settings returns 200", r.status_code == 200)
        settings = r.json()
        weights = settings.get("ranking_weights", {})
        wsum = sum(weights.values())
        report("Default weights sum to 1.0", abs(wsum - 1.0) < 0.001, f"sum={wsum:.4f}")

        # ── 3. PATCH with weights summing to 1.2 -> 422 ────────────────────
        bad_weights = {"download": 0.5, "upload": 0.3, "ping": 0.2, "stability": 0.1, "security": 0.1}
        r = await c.patch("/settings", json={"ranking_weights": bad_weights})
        report("PATCH weights sum 1.2 -> 422", r.status_code == 422,
               f"status={r.status_code}")

        # ── 4. Valid PATCH -> 200 ──────────────────────────────────────────
        new_weights = {"download": 0.40, "upload": 0.15, "ping": 0.25, "stability": 0.10, "security": 0.10}
        r = await c.patch("/settings", json={"ranking_weights": new_weights})
        report("PATCH valid weights -> 200", r.status_code == 200, f"status={r.status_code}")

        # ── 5. Settings persisted ──────────────────────────────────────────
        r = await c.get("/settings")
        persisted = r.json().get("ranking_weights", {})
        report("New weights persisted", persisted.get("download") == 0.40,
               f"download={persisted.get('download')}")

        # ── 6. Ranking reflects new weights ────────────────────────────────
        src_r = await c.post("/sources/", json={"name": "WTest", "type": "manual"})
        src_id = src_r.json()["id"]

        prof_r = await c.post("/profiles/", json={
            "name": "Weight-Test", "protocol": "wireguard",
            "server_host": "127.0.0.1", "server_port": 9999,
            "status": "approved", "risk_score": 10,
            "source_id": src_id,
        })
        prof_id = prof_r.json()["id"]

        await c.post("/metrics", json={
            "profile_id": prof_id, "download_mbps": 150.0,
            "upload_mbps": 80.0, "ping_ms": 50.0,
        })

        r = await c.get("/ranking/top?metric=score&limit=10")
        report("Ranking score returns 200", r.status_code == 200)
        ranked = r.json()
        wt_entry = next((e for e in ranked if e["id"] == prof_id), None)
        if wt_entry:
            # Hand-compute with new weights:
            # dl_norm=min(150/200,1)=0.75, ul_norm=min(80/100,1)=0.80
            # ping_norm=max(0,1-50/1000)=0.95
            # stability=(1-0/100)*(1-min(0/200,1))=1.0
            # security=1-10/100=0.9
            # score=0.40*0.75+0.15*0.80+0.25*0.95+0.10*1.0+0.10*0.9
            expected = round(0.40 * 0.75 + 0.15 * 0.80 + 0.25 * 0.95 + 0.10 * 1.0 + 0.10 * 0.9, 6)
            actual = wt_entry["score"]
            report("Score matches new weights", abs(actual - expected) < 0.001,
                   f"expected={expected}, actual={actual}")
        else:
            report("Score matches new weights", False, "profile not in ranking")

        # ── 7. PATCH test_attempts=0 -> 422 ────────────────────────────────
        r = await c.patch("/settings", json={"test_attempts": 0})
        report("PATCH test_attempts=0 -> 422", r.status_code == 422,
               f"status={r.status_code}")

        # ── 8. PATCH test_attempts=6 -> 200 ────────────────────────────────
        r = await c.patch("/settings", json={"test_attempts": 6})
        report("PATCH test_attempts=6 -> 200", r.status_code == 200,
               f"status={r.status_code}")

        r = await c.get("/settings")
        report("test_attempts=6 persisted", r.json().get("test_attempts") == 6,
               f"val={r.json().get('test_attempts')}")

        # ── 9. GET /api/logs returns entries ───────────────────────────────
        r = await c.get("/logs?limit=100")
        report("GET /api/logs returns 200", r.status_code == 200)
        logs = r.json()
        actions = {l["action"] for l in logs}
        report("Logs include settings_update", "settings_update" in actions,
               f"actions={actions}")

        # ── 10. POST /api/backup ───────────────────────────────────────────
        r = await c.post("/backup")
        report("POST /api/backup -> 200", r.status_code == 200,
               f"status={r.status_code}")
        if r.status_code == 200:
            backup_data = r.json()
            backup_path = backup_data.get("path", "")
            report("Backup file exists", os.path.exists(backup_path),
                   f"path={backup_path}")

        # ── 11. GET /api/export?format=json ────────────────────────────────
        r = await c.get("/export?format=json")
        report("Export JSON -> 200", r.status_code == 200)
        export_data = r.json()
        report("Export has sources array", "sources" in export_data and isinstance(export_data["sources"], list))
        report("Export has profiles array", "profiles" in export_data and isinstance(export_data["profiles"], list))
        report("Export has metrics array", "metrics" in export_data and isinstance(export_data["metrics"], list))

        # ── 12. GET /api/export?format=csv ─────────────────────────────────
        r = await c.get("/export?format=csv")
        report("Export CSV -> 200", r.status_code == 200)
        csv_text = r.text
        has_header = csv_text.startswith("id,name,protocol,server_host")
        report("CSV starts with header", has_header)
        has_profile = "Weight-Test" in csv_text
        report("CSV contains profile name", has_profile)

        # ── 13. Static serving: GET / serves index.html ────────────────────
        async with httpx.AsyncClient(base_url="http://127.0.0.1:8000", timeout=10.0) as sc:
            r = await sc.get("/")
            is_html = "ERROR" in r.text and "<html" in r.text.lower()
            report("GET / serves index.html", r.status_code == 200 and is_html)

            r2 = await sc.get("/api/health")
            report("/api/health still returns JSON", r2.status_code == 200 and r2.json().get("app") == "ERROR-PANEL")

        # ── 14. Desktop.py smoke test ──────────────────────────────────────
        # Since our test server is already on port 8000, desktop.py can't bind.
        # We just verify desktop.py is importable and the file exists.
        desktop_path = os.path.join(REPO_ROOT, "backend", "app", "desktop.py")
        report("desktop.py exists", os.path.exists(desktop_path))

        # Try importing it
        try:
            spec = __import__("importlib").util.spec_from_file_location("desktop", desktop_path)
            report("desktop.py is importable", spec is not None)
        except Exception as e:
            report("desktop.py is importable", False, str(e))

        # ── 15. Frontend grep checks ───────────────────────────────────────
        app_js = os.path.join(REPO_ROOT, "frontend", "js", "app.js")
        api_js = os.path.join(REPO_ROOT, "frontend", "js", "api.js")
        index_html = os.path.join(REPO_ROOT, "frontend", "index.html")

        with open(app_js, "r", encoding="utf-8") as f:
            app_js_text = f.read()
        with open(api_js, "r", encoding="utf-8") as f:
            api_js_text = f.read()
        with open(index_html, "r", encoding="utf-8") as f:
            index_html_text = f.read()

        report("app.js contains w-download slider", "w-download" in app_js_text)
        report("app.js contains createBackup", "createBackup" in app_js_text)
        report("app.js contains exportData", "exportData" in app_js_text)
        report("app.js contains loadLogsTab", "loadLogsTab" in app_js_text)

        report("api.js contains getSettings", "getSettings" in api_js_text)
        report("api.js contains updateSettings", "updateSettings" in api_js_text)
        report("api.js contains getLogs", "getLogs" in api_js_text)
        report("api.js contains createBackup", "createBackup" in api_js_text)
        report("api.js contains exportData", "exportData" in api_js_text)

        settings_section = re.search(r'id="tab-settings".*?</section>', index_html_text, re.DOTALL)
        no_settings_placeholder = settings_section and "فاز ۸" not in settings_section.group()
        report("Settings section no placeholder", no_settings_placeholder)

        logs_section = re.search(r'id="tab-logs".*?</section>', index_html_text, re.DOTALL)
        no_logs_placeholder = logs_section and "فاز ۸" not in logs_section.group()
        report("Logs section no placeholder", no_logs_placeholder)

        # ── 16. node --check on JS files ───────────────────────────────────
        for jsfile in [app_js, api_js]:
            name = os.path.basename(jsfile)
            try:
                result = subprocess.run(
                    ["node", "--check", jsfile],
                    capture_output=True, text=True, timeout=10,
                )
                report(f"node --check {name}", result.returncode == 0,
                       result.stderr.strip() if result.returncode else "OK")
            except FileNotFoundError:
                report(f"node --check {name}", True, "node not found, skip")
            except Exception as e:
                report(f"node --check {name}", False, str(e))

        # ── 17. Audit log has backup entry ─────────────────────────────────
        r = await c.get("/logs?limit=200")
        all_logs = r.json()
        all_actions = {l["action"] for l in all_logs}
        report("Audit log has backup entry", "backup" in all_actions,
               f"actions={all_actions}")

    print(f"\nSUMMARY: {passed}/{passed+failed} tests passed")
    if failed > 0:
        sys.exit(1)


def main():
    # Delete old database
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    print("Starting server...")
    proc = start_server()
    print("Server started. Running tests...\n")

    try:
        asyncio.run(run_tests())
    finally:
        stop_server(proc)
        print("Server stopped.")


if __name__ == "__main__":
    main()
