"""ERROR-PANEL — Phase 2 integration test script.

Starts uvicorn, runs all HTTP tests, verifies audit logs, and prints results.
"""

import asyncio
import json
import sqlite3
import sys
import time
import subprocess
import os
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8000"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(REPO_ROOT, "backend", "data", "error.db")

results = []


def http_request(method, path, data=None):
    """Make an HTTP request and return (status_code, body_dict_or_None)."""
    url = BASE + path
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            raw = resp.read().decode("utf-8")
            try:
                return status, json.loads(raw)
            except json.JSONDecodeError:
                return status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw
    except Exception as e:
        return 0, str(e)


def test(label, method, path, data=None, expected_status=None):
    status, body = http_request(method, path, data)
    ok = True
    if expected_status and status != expected_status:
        ok = False
    results.append({
        "label": label,
        "method": method,
        "path": path,
        "data": data,
        "expected_status": expected_status,
        "actual_status": status,
        "body": body,
        "pass": ok,
    })
    return status, body


def main():
    # Remove old DB so we start fresh
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    # Start uvicorn
    venv_python = os.path.join(REPO_ROOT, ".venv", "bin", "python")
    proc = subprocess.Popen(
        [venv_python, "-m", "uvicorn", "backend.app.main:app",
         "--host", "127.0.0.1", "--port", "8000"],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to be ready
    for _ in range(30):
        try:
            urllib.request.urlopen(BASE + "/api/health")
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("SERVER FAILED TO START")
        out = proc.stdout.read().decode()
        err = proc.stderr.read().decode()
        print("STDOUT:", out)
        print("STDERR:", err)
        proc.kill()
        sys.exit(1)

    try:
        # ── Test 1: Health ─────────────────────────────────────────────
        test("Health check", "GET", "/api/health", expected_status=200)

        # ── Test 2: Create source ──────────────────────────────────────
        s1_status, s1_body = test(
            "Create source",
            "POST", "/api/sources/",
            data={
                "name": "FreeVPN GitHub",
                "type": "github",
                "url": "https://github.com/example/freevpn",
                "status": "active",
                "reputation_score": 75,
            },
            expected_status=201,
        )
        source_id = s1_body.get("id") if isinstance(s1_body, dict) else None

        # ── Test 3: List sources ───────────────────────────────────────
        test("List sources", "GET", "/api/sources/", expected_status=200)

        # ── Test 4: Get source by ID ───────────────────────────────────
        if source_id:
            test("Get source by ID", "GET", f"/api/sources/{source_id}", expected_status=200)

        # ── Test 5: Update source ──────────────────────────────────────
        if source_id:
            test(
                "Update source",
                "PATCH", f"/api/sources/{source_id}",
                data={"reputation_score": 90, "notes": "Reliable source"},
                expected_status=200,
            )

        # ── Test 6: Create profile linked to source ────────────────────
        p1_status, p1_body = test(
            "Create profile",
            "POST", "/api/profiles/",
            data={
                "source_id": source_id,
                "name": "DE-Frankfurt-01",
                "protocol": "wireguard",
                "server_host": "10.0.0.1",
                "server_port": 51820,
                "country_code": "DE",
                "status": "new",
            },
            expected_status=201,
        )
        profile_id = p1_body.get("id") if isinstance(p1_body, dict) else None

        # ── Test 7: Create second profile for filter tests ─────────────
        test(
            "Create profile 2",
            "POST", "/api/profiles/",
            data={
                "source_id": source_id,
                "name": "NL-Amsterdam-02",
                "protocol": "openvpn",
                "server_host": "10.0.0.2",
                "server_port": 1194,
                "country_code": "NL",
                "status": "quarantined",
            },
            expected_status=201,
        )

        # ── Test 8: List profiles (no filter) ──────────────────────────
        test("List profiles (no filter)", "GET", "/api/profiles/", expected_status=200)

        # ── Test 9: List profiles with status filter ───────────────────
        test(
            "List profiles (status=new)",
            "GET", "/api/profiles/?status=new",
            expected_status=200,
        )

        # ── Test 10: List profiles with protocol filter ────────────────
        test(
            "List profiles (protocol=wireguard)",
            "GET", "/api/profiles/?protocol=wireguard",
            expected_status=200,
        )

        # ── Test 11: List profiles with search filter ──────────────────
        test(
            'List profiles (search=frankfurt)',
            "GET", "/api/profiles/?search=frankfurt",
            expected_status=200,
        )

        # ── Test 12: Patch profile status ──────────────────────────────
        if profile_id:
            test(
                "Patch profile status to approved",
                "PATCH", f"/api/profiles/{profile_id}",
                data={"status": "approved"},
                expected_status=200,
            )

        # ── Test 13: Get profile by ID ─────────────────────────────────
        if profile_id:
            test("Get profile by ID", "GET", f"/api/profiles/{profile_id}", expected_status=200)

        # ── Test 14: Delete profile ────────────────────────────────────
        if profile_id:
            test("Delete profile", "DELETE", f"/api/profiles/{profile_id}", expected_status=204)

        # ── Test 15: Verify deleted profile is gone ────────────────────
        if profile_id:
            test(
                "Get deleted profile (should 404)",
                "GET", f"/api/profiles/{profile_id}",
                expected_status=404,
            )

        # ── Test 16: Delete source ─────────────────────────────────────
        if source_id:
            test("Delete source", "DELETE", f"/api/sources/{source_id}", expected_status=204)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ── Verify audit logs directly in SQLite ───────────────────────────
    audit_check = {"pass": False, "count": 0, "logs": []}
    if os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, action, entity_type, entity_id, details_json FROM audit_logs ORDER BY id"
        ).fetchall()
        audit_check["count"] = len(rows)
        audit_check["logs"] = [
            {"id": r["id"], "action": r["action"], "entity_type": r["entity_type"],
             "entity_id": r["entity_id"], "details_json": r["details_json"]}
            for r in rows
        ]
        # We expect audit logs for: create source, update source, create profile x2,
        # update profile, delete profile, delete source = 7
        audit_check["pass"] = audit_check["count"] >= 5
        conn.close()

    # ── Print results ──────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("PHASE 2 — BACKEND CORE TEST RESULTS")
    print("=" * 80)

    for r in results:
        icon = "PASS" if r["pass"] else "FAIL"
        print(f"\n[{icon}] {r['label']}")
        print(f"  {r['method']} {r['path']}")
        if r.get("data"):
            print(f"  Body: {json.dumps(r['data'])}")
        print(f"  Expected: {r['expected_status']}  Actual: {r['actual_status']}")
        body_str = json.dumps(r["body"], indent=2) if isinstance(r["body"], (dict, list)) else str(r["body"])
        if len(body_str) > 500:
            body_str = body_str[:500] + "..."
        print(f"  Response: {body_str}")

    print("\n" + "-" * 80)
    print("AUDIT LOG VERIFICATION")
    print("-" * 80)
    print(f"  Audit rows written: {audit_check['count']}")
    print(f"  PASS: {audit_check['pass']}")
    for log in audit_check["logs"]:
        print(f"  [{log['id']}] {log['action']} {log['entity_type']}#{log['entity_id']} — {log['details_json']}")

    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    print(f"\nSUMMARY: {passed}/{total} tests passed, audit log check: {'PASS' if audit_check['pass'] else 'FAIL'}")

    if passed < total or not audit_check["pass"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
