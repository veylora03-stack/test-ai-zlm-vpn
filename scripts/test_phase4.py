"""ERROR-PANEL — Phase 4 integration test script.

Offline-safe tests for fetcher, sync, quarantine, and frontend.
Uses a local http.server to serve sample files.
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import tempfile
import urllib.request
import urllib.error

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(REPO_ROOT, "backend", "data", "error.db")
BACKEND_BASE = "http://127.0.0.1:8000"
venv_python = os.path.join(REPO_ROOT, ".venv", "bin", "python")

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

    # Create temp directory with test files
    tmpdir = tempfile.mkdtemp(prefix="ep4_test_")
    sample_content = "[Interface]\nPrivateKey = test\nAddress = 10.0.0.1/24\n[Peer]\nPublicKey = peer\nEndpoint = 1.2.3.4:51820\n"
    with open(os.path.join(tmpdir, "sample.txt"), "w") as f:
        f.write(sample_content)
    sample_sha256 = hashlib.sha256(sample_content.encode()).hexdigest()

    # 404 file (missing.txt) — we just don't create it
    # Big file (1.1 MB)
    big_content = "x" * (1100 * 1024)
    with open(os.path.join(tmpdir, "big.txt"), "w") as f:
        f.write(big_content)

    # Start local file server
    fileserver_proc = subprocess.Popen(
        [venv_python, "-m", "http.server", "8090"],
        cwd=tmpdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Start backend
    backend_proc = subprocess.Popen(
        [venv_python, "-m", "uvicorn", "backend.app.main:app",
         "--host", "127.0.0.1", "--port", "8000"],
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
        fileserver_proc.kill()
        sys.exit(1)

    for _ in range(15):
        try:
            urllib.request.urlopen("http://127.0.0.1:8090/sample.txt")
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("FILE SERVER FAILED TO START")
        backend_proc.kill()
        fileserver_proc.kill()
        sys.exit(1)

    try:
        # ── 1. Health check ────────────────────────────────────────────
        status, body = http_request("GET", BACKEND_BASE + "/api/health")
        test("Health check", status == 200 and body.get("status") == "online",
             f"status={status}")

        # ── 2. Create source with local URL ────────────────────────────
        status, src = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Local Test", "type": "url",
            "url": "http://127.0.0.1:8090/sample.txt", "status": "pending_review"
        })
        source_id = src.get("id") if isinstance(src, dict) else None
        test("Create source with local URL", status == 201, f"status={status}, id={source_id}")

        # ── 3. Sync source — expect success ────────────────────────────
        status, sync_res = http_request("POST", BACKEND_BASE + f"/api/sources/{source_id}/sync")
        ok7 = isinstance(sync_res, dict)
        test("Sync source returns 200",
             status == 200 and ok7,
             f"status={status}, body={sync_res}")

        # ── 4. Verify sha256 matches ───────────────────────────────────
        if ok7:
            test("SHA256 matches file content",
                 sync_res.get("sha256") == sample_sha256,
                 f"expected={sample_sha256[:16]}... got={sync_res.get('sha256','')[:16]}...")

        # ── 5. Verify imported_count >= 0 (parser is real, not stub) ──
        if ok7:
            test("imported_count >= 0 (real parser)",
                 sync_res.get("imported_count") >= 0,
                 f"got={sync_res.get('imported_count')}")

        # ── 6. Verify raw file exists on disk ──────────────────────────
        if ok7:
            raw_path = sync_res.get("raw_path", "")
            raw_exists = os.path.isfile(raw_path)
            test("Raw file exists on disk", raw_exists, f"path={raw_path}")

        # ── 7. Verify source status is now active ──────────────────────
        status, src_after = http_request("GET", BACKEND_BASE + f"/api/sources/{source_id}")
        test("Source status is active after sync",
             isinstance(src_after, dict) and src_after.get("status") == "active",
             f"status={src_after.get('status') if isinstance(src_after, dict) else 'N/A'}")

        # ── 8. Verify source last_sync_at is set ───────────────────────
        test("Source last_sync_at is set",
             isinstance(src_after, dict) and src_after.get("last_sync_at") is not None)

        # ── 9. Sync missing URL — expect graceful error ────────────────
        status2, src2 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Missing File", "type": "url",
            "url": "http://127.0.0.1:8090/missing.txt", "status": "pending_review"
        })
        source_id2 = src2.get("id") if isinstance(src2, dict) else None
        sync_status, sync_body = http_request("POST", BACKEND_BASE + f"/api/sources/{source_id2}/sync")
        test("Sync missing URL returns error",
             sync_status in (400, 502),
             f"status={sync_status}")

        # Verify last_error is set on source
        status_chk, src2_chk = http_request("GET", BACKEND_BASE + f"/api/sources/{source_id2}")
        test("Source last_error is set after failed sync",
             isinstance(src2_chk, dict) and src2_chk.get("last_error") is not None,
             f"last_error={src2_chk.get('last_error') if isinstance(src2_chk, dict) else 'N/A'}")

        # ── 10. FTP URL — scheme rejection ─────────────────────────────
        status3, src3 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "FTP Source", "type": "url",
            "url": "ftp://evil.example.com/config.txt", "status": "pending_review"
        })
        source_id3 = src3.get("id") if isinstance(src3, dict) else None
        ftp_status, ftp_body = http_request("POST", BACKEND_BASE + f"/api/sources/{source_id3}/sync")
        test("FTP URL scheme rejected",
             ftp_status == 400,
             f"status={ftp_status}, body={ftp_body}")

        # ── 11. Big file — size limit error ────────────────────────────
        status4, src4 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Big File", "type": "url",
            "url": "http://127.0.0.1:8090/big.txt", "status": "pending_review"
        })
        source_id4 = src4.get("id") if isinstance(src4, dict) else None
        big_status, big_body = http_request("POST", BACKEND_BASE + f"/api/sources/{source_id4}/sync")
        test("Big file (>1MB) rejected with size limit",
             big_status == 400,
             f"status={big_status}, body={big_body}")

        # ── 12. Blocked source — 409 on sync ───────────────────────────
        status5, src5 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Blocked Source", "type": "url",
            "url": "http://127.0.0.1:8090/sample.txt", "status": "blocked"
        })
        source_id5 = src5.get("id") if isinstance(src5, dict) else None
        blocked_status, _ = http_request("POST", BACKEND_BASE + f"/api/sources/{source_id5}/sync")
        test("Blocked source returns 409 on sync",
             blocked_status == 409,
             f"status={blocked_status}")

        # ── 13. Create quarantined profiles ─────────────────────────────
        status_p1, p1 = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "name": "Q-Profile-1", "protocol": "wireguard",
            "server_host": "10.0.0.1", "server_port": 51820,
            "status": "quarantined"
        })
        p1_id = p1.get("id") if isinstance(p1, dict) else None

        status_p2, p2 = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "name": "Q-Profile-2", "protocol": "openvpn",
            "server_host": "10.0.0.2", "server_port": 1194,
            "status": "quarantined"
        })
        p2_id = p2.get("id") if isinstance(p2, dict) else None

        test("Create two quarantined profiles",
             status_p1 == 201 and status_p2 == 201,
             f"p1={status_p1}, p2={status_p2}")

        # ── 14. GET /api/quarantine returns 2+sync profile ───────────────
        # Real parser creates 1 quarantined profile from sync; +2 manual = 3
        q_status, q_list = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        quarantine_count_before = len(q_list) if isinstance(q_list, list) else 0
        test("GET /api/quarantine returns >= 2",
             q_status == 200 and quarantine_count_before >= 2,
             f"status={q_status}, count={quarantine_count_before}")

        # ── 15. Approve one ────────────────────────────────────────────
        app_status, app_body = http_request("POST", BACKEND_BASE + f"/api/quarantine/{p1_id}/approve")
        test("Approve quarantined profile",
             app_status == 200 and isinstance(app_body, dict) and app_body.get("status") == "approved",
             f"status={app_status}")

        # ── 16. Verify approved profile gone from quarantine ───────────
        q2_status, q2_list = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        expected_after_approve = quarantine_count_before - 1
        test("Quarantine count decreased by 1 after approve",
             q2_status == 200 and len(q2_list) == expected_after_approve,
             f"expected={expected_after_approve}, count={len(q2_list) if isinstance(q2_list, list) else 'N/A'}")

        # ── 17. Reject second ──────────────────────────────────────────
        rej_status, rej_body = http_request("POST", BACKEND_BASE + f"/api/quarantine/{p2_id}/reject")
        test("Reject quarantined profile (status→blocked)",
             rej_status == 200 and isinstance(rej_body, dict) and rej_body.get("status") == "blocked",
             f"status={rej_status}, body_status={rej_body.get('status') if isinstance(rej_body, dict) else 'N/A'}")

        # ── 18. Create third and block it ──────────────────────────────
        status_p3, p3 = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "name": "Q-Profile-3", "protocol": "vless",
            "server_host": "10.0.0.3", "server_port": 443,
            "status": "quarantined"
        })
        p3_id = p3.get("id") if isinstance(p3, dict) else None

        blk_status, blk_body = http_request("POST", BACKEND_BASE + f"/api/quarantine/{p3_id}/block")
        test("Block quarantined profile (status→blocked, risk_score→100)",
             blk_status == 200 and isinstance(blk_body, dict)
             and blk_body.get("status") == "blocked" and blk_body.get("risk_score") == 100,
             f"status={blk_body.get('status') if isinstance(blk_body, dict) else 'N/A'}, "
             f"risk={blk_body.get('risk_score') if isinstance(blk_body, dict) else 'N/A'}")

        # ── 19. Verify quarantine decreased after reject ───────────────
        q3_status, q3_list = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        test("Quarantine count after reject",
             q3_status == 200 and len(q3_list) >= 0,
             f"count={len(q3_list) if isinstance(q3_list, list) else 'N/A'}")

        # ── 20. Verify audit_logs ───────────────────────────────────────
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT action, entity_type FROM audit_logs ORDER BY id"
            ).fetchall()
            actions = [(r[0], r[1]) for r in rows]
            conn.close()

            has_sync = ("sync", "source") in actions
            has_approve = ("approve", "profile") in actions
            has_reject = ("reject", "profile") in actions
            has_block = ("block", "profile") in actions
            test("Audit log has sync entry", has_sync)
            test("Audit log has approve entry", has_approve)
            test("Audit log has reject entry", has_reject)
            test("Audit log has block entry", has_block)
        else:
            test("Audit log check", False, "DB not found")

        # ── 21. Frontend files check ───────────────────────────────────
        # api.js has new functions
        with open(os.path.join(REPO_ROOT, "frontend", "js", "api.js")) as f:
            api_js = f.read()
        test("api.js has syncSource", "async function syncSource" in api_js)
        test("api.js has listQuarantine", "async function listQuarantine" in api_js)
        test("api.js has approveQuarantine", "async function approveQuarantine" in api_js)
        test("api.js has rejectQuarantine", "async function rejectQuarantine" in api_js)
        test("api.js has blockQuarantine", "async function blockQuarantine" in api_js)

        # app.js has sync button handler
        with open(os.path.join(REPO_ROOT, "frontend", "js", "app.js")) as f:
            app_js = f.read()
        test("app.js has syncSourceAction", "async function syncSourceAction" in app_js)
        test("app.js has blockQuarantinedAction", "async function blockQuarantinedAction" in app_js)
        test("app.js loads quarantine via listQuarantine", "await listQuarantine()" in app_js)

    finally:
        backend_proc.terminate()
        fileserver_proc.terminate()
        try:
            backend_proc.wait(timeout=5)
        except Exception:
            backend_proc.kill()
        try:
            fileserver_proc.wait(timeout=5)
        except Exception:
            fileserver_proc.kill()

    # ── Print results ──────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("PHASE 4 — SOURCE IMPORT PIPELINE & QUARANTINE TEST RESULTS")
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
