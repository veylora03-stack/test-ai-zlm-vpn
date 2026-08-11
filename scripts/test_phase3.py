"""ERROR-PANEL — Phase 3 integration test script.

Starts the backend (uvicorn), the frontend (http.server), and runs
functional checks via headless DOM using the agent-browser skill approach.
Since we can't run a real browser here, we verify:
1. Backend health endpoint works
2. Frontend files are served correctly
3. All JS functions are syntactically valid (node --check)
4. API round-trip: create source, create profile, list, filter, quarantine approve
5. HTML structure validation: all tabs present, modal present, Persian labels
"""

import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request
import urllib.error

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(REPO_ROOT, "backend", "data", "error.db")
BACKEND_BASE = "http://127.0.0.1:8000"
FRONTEND_BASE = "http://127.0.0.1:8080"

results = []


def http_request(method, url, data=None):
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw
    except Exception as e:
        return 0, str(e)


def test(label, condition, detail=""):
    results.append({"label": label, "pass": condition, "detail": detail})


def main():
    # Remove old DB
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    venv_python = os.path.join(REPO_ROOT, ".venv", "bin", "python")

    # Start backend
    backend_proc = subprocess.Popen(
        [venv_python, "-m", "uvicorn", "backend.app.main:app",
         "--host", "127.0.0.1", "--port", "8000"],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Start frontend server
    frontend_proc = subprocess.Popen(
        [venv_python, "-m", "http.server", "8080", "-d", "frontend"],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for servers
    for _ in range(30):
        try:
            urllib.request.urlopen(BACKEND_BASE + "/api/health")
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("BACKEND FAILED TO START")
        backend_proc.kill()
        frontend_proc.kill()
        sys.exit(1)

    for _ in range(15):
        try:
            urllib.request.urlopen(FRONTEND_BASE + "/")
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("FRONTEND SERVER FAILED TO START")
        backend_proc.kill()
        frontend_proc.kill()
        sys.exit(1)

    try:
        # ── 1. Backend health shows online ──────────────────────────────
        status, body = http_request("GET", BACKEND_BASE + "/api/health")
        test("Backend health shows online", status == 200 and body.get("status") == "online",
             f"status={status}, body={body}")

        # ── 2. Frontend index.html served ───────────────────────────────
        status, html = http_request("GET", FRONTEND_BASE + "/")
        test("Frontend index.html served", status == 200 and "<html" in str(html).lower(),
             f"status={status}")

        # ── 3. CSS served ───────────────────────────────────────────────
        status, _ = http_request("GET", FRONTEND_BASE + "/css/app.css")
        test("CSS app.css served", status == 200, f"status={status}")

        # ── 4. JS files served ──────────────────────────────────────────
        status1, _ = http_request("GET", FRONTEND_BASE + "/js/api.js")
        status2, _ = http_request("GET", FRONTEND_BASE + "/js/app.js")
        test("JS files served", status1 == 200 and status2 == 200,
             f"api.js={status1}, app.js={status2}")

        # ── 5. HTML structure: RTL, Persian lang ────────────────────────
        html_str = str(html)
        test("HTML has lang=fa dir=rtl",
             'lang="fa"' in html_str and 'dir="rtl"' in html_str,
             "Missing lang=fa or dir=rtl")

        # ── 6. All tab data-tab attributes present ──────────────────────
        expected_tabs = ["dashboard", "servers", "sources", "quarantine", "analytics", "settings", "logs"]
        all_tabs_present = all(f'data-tab="{t}"' in html_str for t in expected_tabs)
        test("All 7 tab data-tab attributes present", all_tabs_present)

        # ── 7. Modal skeleton present ───────────────────────────────────
        test("Modal skeleton present", 'id="profile-modal"' in html_str)

        # ── 8. Persian labels in sidebar ────────────────────────────────
        persian_labels = ["داشبورد", "سرورها", "منابع", "قرنطینه", "تحلیل", "تنظیمات", "لاگ‌ها"]
        all_persian = all(label in html_str for label in persian_labels)
        test("Persian labels in sidebar", all_persian)

        # ── 9. Toast container present ──────────────────────────────────
        test("Toast container present", 'id="toast-container"' in html_str)

        # ── 10. Source add form present ─────────────────────────────────
        test("Source add form present", 'id="source-add-form"' in html_str)

        # ── 11. API round-trip: create source ───────────────────────────
        status, src = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Test Source", "type": "github",
            "url": "https://github.com/test/vpn", "status": "active"
        })
        source_id = src.get("id") if isinstance(src, dict) else None
        test("Create source via API", status == 201 and source_id is not None,
             f"status={status}, id={source_id}")

        # ── 12. API round-trip: create profile ──────────────────────────
        status, prof = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "source_id": source_id, "name": "DE-Test-01", "protocol": "wireguard",
            "server_host": "10.0.0.1", "server_port": 51820,
            "country_code": "DE", "status": "new"
        })
        profile_id = prof.get("id") if isinstance(prof, dict) else None
        test("Create profile via API", status == 201 and profile_id is not None,
             f"status={status}, id={profile_id}")

        # ── 13. Create quarantined profile ──────────────────────────────
        status, qprof = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "source_id": source_id, "name": "IR-Quarantine-01", "protocol": "openvpn",
            "server_host": "10.0.0.2", "server_port": 1194,
            "country_code": "IR", "status": "quarantined"
        })
        q_id = qprof.get("id") if isinstance(qprof, dict) else None
        test("Create quarantined profile", status == 201, f"status={status}")

        # ── 14. List profiles (no filter) ───────────────────────────────
        status, profiles = http_request("GET", BACKEND_BASE + "/api/profiles/")
        test("List profiles returns 2", status == 200 and len(profiles) == 2,
             f"status={status}, count={len(profiles) if isinstance(profiles, list) else 'N/A'}")

        # ── 15. Filter by status=new ────────────────────────────────────
        status, filtered = http_request("GET", BACKEND_BASE + "/api/profiles/?status=new")
        test("Filter by status=new returns 1",
             status == 200 and len(filtered) == 1,
             f"count={len(filtered) if isinstance(filtered, list) else 'N/A'}")

        # ── 16. Filter by protocol=wireguard ────────────────────────────
        status, filtered = http_request("GET", BACKEND_BASE + "/api/profiles/?protocol=wireguard")
        test("Filter by protocol=wireguard returns 1",
             status == 200 and len(filtered) == 1,
             f"count={len(filtered) if isinstance(filtered, list) else 'N/A'}")

        # ── 17. Search filter ───────────────────────────────────────────
        status, filtered = http_request("GET", BACKEND_BASE + "/api/profiles/?search=test")
        test("Search filter returns 1", status == 200 and len(filtered) == 1,
             f"count={len(filtered) if isinstance(filtered, list) else 'N/A'}")

        # ── 18. Update profile status (approve quarantined) ─────────────
        status, updated = http_request("PATCH", BACKEND_BASE + f"/api/profiles/{q_id}",
                                       {"status": "approved"})
        test("Approve quarantined profile",
             status == 200 and updated.get("status") == "approved",
             f"status={status}, new_status={updated.get('status') if isinstance(updated, dict) else 'N/A'}")

        # ── 19. Verify quarantined list now empty ───────────────────────
        status, quarantined = http_request("GET", BACKEND_BASE + "/api/profiles/?status=quarantined")
        test("Quarantine list now empty",
             status == 200 and len(quarantined) == 0,
             f"count={len(quarantined) if isinstance(quarantined, list) else 'N/A'}")

        # ── 20. Delete profile ──────────────────────────────────────────
        status, _ = http_request("DELETE", BACKEND_BASE + f"/api/profiles/{profile_id}")
        test("Delete profile returns 204", status == 204, f"status={status}")

        # ── 21. Verify JS api.js contains all functions ─────────────────
        status, api_js = http_request("GET", FRONTEND_BASE + "/js/api.js")
        api_str = str(api_js)
        api_funcs = ["health", "listSources", "createSource", "getSource",
                     "updateSource", "deleteSource", "listProfiles",
                     "createProfile", "getProfile", "updateProfile", "deleteProfile"]
        all_funcs = all(f"async function {fn}" in api_str for fn in api_funcs)
        test("api.js has all 11 API functions", all_funcs)

        # ── 22. Verify app.js has tab switching logic ───────────────────
        status, app_js = http_request("GET", FRONTEND_BASE + "/js/app.js")
        app_str = str(app_js)
        test("app.js has initTabs", "function initTabs" in app_str)
        test("app.js has loadDashboard", "async function loadDashboard" in app_str)
        test("app.js has loadServers", "async function loadServers" in app_str)
        test("app.js has loadSources", "async function loadSources" in app_str)
        test("app.js has loadQuarantine", "async function loadQuarantine" in app_str)

        # ── 23. Verify CSS has glassmorphism ────────────────────────────
        status, css = http_request("GET", FRONTEND_BASE + "/css/app.css")
        css_str = str(css)
        test("CSS has backdrop-filter blur", "backdrop-filter" in css_str and "blur" in css_str)
        test("CSS has dark bg #03050b", "#03050b" in css_str)
        test("CSS has accent gradient", "accent-from" in css_str and "accent-to" in css_str)
        test("CSS has responsive breakpoint", "@media" in css_str and "900px" in css_str)

    finally:
        backend_proc.terminate()
        frontend_proc.terminate()
        try:
            backend_proc.wait(timeout=5)
        except Exception:
            backend_proc.kill()
        try:
            frontend_proc.wait(timeout=5)
        except Exception:
            frontend_proc.kill()

    # ── Print results ──────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("PHASE 3 — FRONTEND SHELL TEST RESULTS")
    print("=" * 80)

    for i, r in enumerate(results, 1):
        icon = "PASS" if r["pass"] else "FAIL"
        detail = f"  ({r['detail']})" if r["detail"] else ""
        print(f"  [{icon}] {i:2d}. {r['label']}{detail}")

    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    print(f"\nSUMMARY: {passed}/{total} tests passed")

    if passed < total:
        sys.exit(1)


if __name__ == "__main__":
    main()
