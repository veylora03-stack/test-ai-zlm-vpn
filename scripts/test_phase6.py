"""ERROR-PANEL — Phase 6 integration test script.

Offline-safe tests for the security scanner, risk scoring, quarantine
integration with latest_scan, and auto-scan during sync.
"""

import base64
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

    tmpdir = tempfile.mkdtemp(prefix="ep6_test_")

    # 1. WireGuard with PrivateKey exposed
    wg_pk = """[Interface]
PrivateKey = ABCDEF123456
Address = 10.0.0.1/24

[Peer]
PublicKey = peerKeyAAA
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
"""
    with open(os.path.join(tmpdir, "wg_pk.txt"), "w") as f:
        f.write(wg_pk)

    # 2. OpenVPN with exec directives
    ovpn_exec = """client
dev tun
proto udp
remote 10.20.30.40 1194
script-security 2
up /usr/bin/malicious.sh
down /usr/bin/malicious.sh
cipher AES-256-CBC
"""
    with open(os.path.join(tmpdir, "ovpn_exec.txt"), "w") as f:
        f.write(ovpn_exec)

    # 3. Raw content with allowInsecure=true for scanner
    insecure_raw = """allowInsecure=true
vmess://eyJwcyI6ICJJbnNlY3VyZS1WTWVzcyIsICJhZGQiOiAiMTEuMjIuMzMuNDQiLCAicG9ydCI6IDQ0MywgImlkIjogInV1aWQtdGVzdC0xMjM0IiwgIm5ldCI6ICJ3cyIsICJ0eXBlIjogIm5vbmUifQ==
"""
    with open(os.path.join(tmpdir, "sub_insecure.txt"), "w") as f:
        f.write(insecure_raw)

    # 4. OpenVPN with weak cipher
    ovpn_weak = """client
dev tun
proto udp
remote 10.20.30.50 1194
cipher BF-CBC
"""
    with open(os.path.join(tmpdir, "ovpn_weak.txt"), "w") as f:
        f.write(ovpn_weak)

    # 5. WireGuard with localhost endpoint
    wg_localhost = """[Interface]
PrivateKey = x
Address = 10.0.0.1/24

[Peer]
PublicKey = peerKeyBBB
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
"""
    with open(os.path.join(tmpdir, "wg_localhost.txt"), "w") as f:
        f.write(wg_localhost)

    # 6. Clean WireGuard from reputable source (DIFFERENT endpoint to avoid dedup)
    wg_clean = """[Interface]
PrivateKey = x
Address = 10.0.0.1/24
DNS = 1.1.1.1

# Germany Frankfurt
[Peer]
PublicKey = peerKeyCCC
Endpoint = 100.200.30.40:51820
AllowedIPs = 0.0.0.0/0
"""
    with open(os.path.join(tmpdir, "wg_clean.txt"), "w") as f:
        f.write(wg_clean)

    # 6b. Second clean WireGuard (for reputable source test, different key/host)
    wg_clean2 = """[Interface]
Address = 10.0.0.2/24
DNS = 1.1.1.1

# Netherlands Amsterdam
[Peer]
PublicKey = peerKeyDDD
Endpoint = 200.100.50.60:51820
AllowedIPs = 0.0.0.0/0
"""
    with open(os.path.join(tmpdir, "wg_clean2.txt"), "w") as f:
        f.write(wg_clean2)

    # 7. Critical case: private key + exec + insecure
    ovpn_critical = """client
dev tun
proto udp
remote 10.20.30.60 1194

<key>
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3v5aP9cR7hK2+mT8J3FxN4qW1bL0p+Y6dR3vX2kQ8j
-----END RSA PRIVATE KEY-----
</key>

script-security 2
up /usr/bin/danger.sh
allowInsecure=true
"""
    with open(os.path.join(tmpdir, "ovpn_critical.txt"), "w") as f:
        f.write(ovpn_critical)

    # Start local file server
    fileserver_proc = subprocess.Popen(
        [venv_python, "-m", "http.server", "8090"],
        cwd=tmpdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    # Start backend
    backend_proc = subprocess.Popen(
        [venv_python, "-m", "uvicorn", "backend.app.main:app",
         "--host", "127.0.0.1", "--port", "8000"],
        cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    for _ in range(30):
        try:
            urllib.request.urlopen(BACKEND_BASE + "/api/health")
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("BACKEND FAILED TO START")
        backend_proc.kill(); fileserver_proc.kill(); sys.exit(1)

    for _ in range(15):
        try:
            urllib.request.urlopen("http://127.0.0.1:8090/wg_pk.txt")
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("FILE SERVER FAILED TO START")
        backend_proc.kill(); fileserver_proc.kill(); sys.exit(1)

    try:
        # ── 1. Health check ────────────────────────────────────────────
        status, body = http_request("GET", BACKEND_BASE + "/api/health")
        test("Health check", status == 200 and body.get("version") is not None,
             f"version={body.get('version') if isinstance(body, dict) else 'N/A'}")

        # ── 2. PrivateKey exposed -> risk >= 35 ────────────────────────
        s1, src1 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "WG-PK", "type": "url",
            "url": "http://127.0.0.1:8090/wg_pk.txt", "status": "pending_review"
        })
        sid1 = src1["id"]
        http_request("POST", BACKEND_BASE + f"/api/sources/{sid1}/sync")
        # Get the quarantined profiles
        q_s, q_b = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        pk_profiles = [p for p in q_b if p.get("source_id") == sid1]
        test("WG with PrivateKey: has profile", len(pk_profiles) >= 1, f"count={len(pk_profiles)}")
        if pk_profiles:
            scan = pk_profiles[0].get("latest_scan")
            test("PrivateKey exposed: risk >= 35",
                 scan is not None and scan.get("risk_score", 0) >= 35,
                 f"risk={scan.get('risk_score') if scan else 'N/A'}")
            pk_warning_codes = [w["code"] for w in (scan.get("warnings") or [])] if scan else []
            test("PrivateKey warning code present",
                 "private_key_exposed" in pk_warning_codes,
                 f"codes={pk_warning_codes}")

        # ── 3. Exec directives -> exec_directives warning ──────────────
        s2, src2 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "OVPN-Exec", "type": "url",
            "url": "http://127.0.0.1:8090/ovpn_exec.txt", "status": "pending_review"
        })
        sid2 = src2["id"]
        http_request("POST", BACKEND_BASE + f"/api/sources/{sid2}/sync")
        q2_s, q2_b = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        exec_profiles = [p for p in q2_b if p.get("source_id") == sid2]
        if exec_profiles:
            scan2 = exec_profiles[0].get("latest_scan")
            codes2 = [w["code"] for w in (scan2.get("warnings") or [])] if scan2 else []
            test("Exec directives warning present", "exec_directives" in codes2,
                 f"codes={codes2}")

        # ── 4. allowInsecure -> allow_insecure warning ─────────────────
        s3, src3 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Sub-Insecure", "type": "url",
            "url": "http://127.0.0.1:8090/sub_insecure.txt", "status": "pending_review"
        })
        sid3 = src3["id"]
        http_request("POST", BACKEND_BASE + f"/api/sources/{sid3}/sync")
        q3_s, q3_b = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        insecure_profiles = [p for p in q3_b if p.get("source_id") == sid3]
        if insecure_profiles:
            scan3 = insecure_profiles[0].get("latest_scan")
            codes3 = [w["code"] for w in (scan3.get("warnings") or [])] if scan3 else []
            test("allowInsecure warning present", "allow_insecure" in codes3,
                 f"codes={codes3}")

        # ── 5. Weak cipher -> weak_cipher warning ──────────────────────
        s4, src4 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "OVPN-Weak", "type": "url",
            "url": "http://127.0.0.1:8090/ovpn_weak.txt", "status": "pending_review"
        })
        sid4 = src4["id"]
        http_request("POST", BACKEND_BASE + f"/api/sources/{sid4}/sync")
        q4_s, q4_b = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        weak_profiles = [p for p in q4_b if p.get("source_id") == sid4]
        if weak_profiles:
            scan4 = weak_profiles[0].get("latest_scan")
            codes4 = [w["code"] for w in (scan4.get("warnings") or [])] if scan4 else []
            test("Weak cipher warning present", "weak_cipher" in codes4,
                 f"codes={codes4}")

        # ── 6. localhost -> localhost_or_private_remote warning ────────
        s5, src5 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "WG-Localhost", "type": "url",
            "url": "http://127.0.0.1:8090/wg_localhost.txt", "status": "pending_review"
        })
        sid5 = src5["id"]
        http_request("POST", BACKEND_BASE + f"/api/sources/{sid5}/sync")
        q5_s, q5_b = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        loc_profiles = [p for p in q5_b if p.get("source_id") == sid5]
        if loc_profiles:
            scan5 = loc_profiles[0].get("latest_scan")
            codes5 = [w["code"] for w in (scan5.get("warnings") or [])] if scan5 else []
            test("localhost_or_private_remote warning present",
                 "localhost_or_private_remote" in codes5, f"codes={codes5}")

        # ── 7. Low reputation source -> low_reputation_source ──────────
        s6, src6 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Low-Rep", "type": "url",
            "url": "http://127.0.0.1:8090/wg_clean.txt",
            "status": "pending_review", "reputation_score": 30
        })
        sid6 = src6["id"]
        http_request("POST", BACKEND_BASE + f"/api/sources/{sid6}/sync")
        q6_s, q6_b = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        lowrep_profiles = [p for p in q6_b if p.get("source_id") == sid6]
        if lowrep_profiles:
            scan6 = lowrep_profiles[0].get("latest_scan")
            codes6 = [w["code"] for w in (scan6.get("warnings") or [])] if scan6 else []
            test("low_reputation_source warning present",
                 "low_reputation_source" in codes6, f"codes={codes6}")

        # ── 8. Clean WG from reputable source -> risk_level low, rec approve ──
        s7, src7 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Clean-Reputable", "type": "url",
            "url": "http://127.0.0.1:8090/wg_clean2.txt",
            "status": "pending_review", "reputation_score": 80
        })
        sid7 = src7["id"]
        http_request("POST", BACKEND_BASE + f"/api/sources/{sid7}/sync")
        q7_s, q7_b = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        clean_profiles = [p for p in q7_b if p.get("source_id") == sid7]
        if clean_profiles:
            scan7 = clean_profiles[0].get("latest_scan")
            test("Clean profile: risk_level = low",
                 scan7 is not None and scan7.get("risk_level") == "low",
                 f"level={scan7.get('risk_level') if scan7 else 'N/A'}")
            test("Clean profile: recommendation = approve",
                 scan7 is not None and scan7.get("recommendation") == "approve",
                 f"rec={scan7.get('recommendation') if scan7 else 'N/A'}")

        # ── 9. Critical case -> risk_level critical, rec block ─────────
        s8, src8 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Critical-Source", "type": "url",
            "url": "http://127.0.0.1:8090/ovpn_critical.txt", "status": "pending_review"
        })
        sid8 = src8["id"]
        http_request("POST", BACKEND_BASE + f"/api/sources/{sid8}/sync")
        q8_s, q8_b = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        crit_profiles = [p for p in q8_b if p.get("source_id") == sid8]
        if crit_profiles:
            scan8 = crit_profiles[0].get("latest_scan")
            test("Critical: risk_level = critical",
                 scan8 is not None and scan8.get("risk_level") == "critical",
                 f"level={scan8.get('risk_level') if scan8 else 'N/A'}, score={scan8.get('risk_score') if scan8 else 'N/A'}")
            test("Critical: recommendation = block",
                 scan8 is not None and scan8.get("recommendation") == "block",
                 f"rec={scan8.get('recommendation') if scan8 else 'N/A'}")
            # Verify profile.risk_score updated
            pid = crit_profiles[0]["id"]
            ps, pb = http_request("GET", BACKEND_BASE + f"/api/profiles/{pid}")
            test("Critical: profile.risk_score updated to 100 cap",
                 isinstance(pb, dict) and pb.get("risk_score") == 100,
                 f"risk_score={pb.get('risk_score') if isinstance(pb, dict) else 'N/A'}")

        # ── 10. POST /api/security/scan/{id} on-demand scan ────────────
        # Use first available quarantined profile
        q_for_scan_s, q_for_scan_b = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        on_demand_ok = False
        scan_history_ok = False
        if q_for_scan_b and len(q_for_scan_b) > 0:
            pid_test = q_for_scan_b[0]["id"]
            scan_s, scan_b = http_request("POST", BACKEND_BASE + f"/api/security/scan/{pid_test}")
            on_demand_ok = scan_s == 200 and isinstance(scan_b, dict) and "risk_level" in scan_b
            test("On-demand scan returns 200", on_demand_ok,
                 f"status={scan_s}, body_keys={list(scan_b.keys()) if isinstance(scan_b, dict) else 'N/A'}")

            # ── 11. GET /api/security/scans/{id} history ──────────────────
            hist_s, hist_b = http_request("GET", BACKEND_BASE + f"/api/security/scans/{pid_test}")
            scan_history_ok = hist_s == 200 and isinstance(hist_b, list) and len(hist_b) >= 2
            test("Scan history has 2+ entries", scan_history_ok,
                 f"count={len(hist_b) if isinstance(hist_b, list) else 'N/A'}")
        else:
            test("On-demand scan returns 200", False, "No quarantined profiles")
            test("Scan history has 2+ entries", False, "No quarantined profiles")

        # ── 12. Quarantine items include latest_scan ───────────────────
        q_s2, q_b2 = http_request("GET", BACKEND_BASE + "/api/quarantine/")
        has_latest_scan = all(
            isinstance(p, dict) and "latest_scan" in p
            for p in q_b2
        )
        test("All quarantine items have latest_scan key", has_latest_scan)

        # ── 13. Sync auto-scan: profiles already have SecurityScan ────
        # Check that all profiles from source sid7 have scans
        ps_all, pb_all = http_request("GET", BACKEND_BASE + "/api/profiles/")
        source7_profiles = [p for p in pb_all if isinstance(p, dict) and p.get("source_id") == sid7]
        auto_scanned = False
        for sp in source7_profiles:
            hist_as, hist_ab = http_request("GET", BACKEND_BASE + f"/api/security/scans/{sp['id']}")
            if isinstance(hist_ab, list) and len(hist_ab) >= 1:
                auto_scanned = True
        test("Sync auto-scan: profiles have scan history", auto_scanned)

        # ── 14. Audit log contains scan entries ────────────────────────
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT action, entity_type FROM audit_logs WHERE action='scan'"
            ).fetchall()
            conn.close()
            test("Audit log has scan entries", len(rows) > 0, f"count={len(rows)}")
        else:
            test("Audit log check", False, "DB not found")

        # ── 15. JS syntax check ─────────────────────────────────────────
        for jsf in ["api.js", "app.js"]:
            r = subprocess.run(
                ["node", "--check", os.path.join(REPO_ROOT, "frontend", "js", jsf)],
                capture_output=True, text=True
            )
            test(f"node --check {jsf}", r.returncode == 0,
                 r.stderr.strip() if r.returncode != 0 else "OK")

        # ── 16. Frontend has new functions and risk badges ─────────────
        with open(os.path.join(REPO_ROOT, "frontend", "js", "api.js")) as f:
            api_js = f.read()
        test("api.js has scanProfile", "async function scanProfile" in api_js)
        test("api.js has getScans", "async function getScans" in api_js)

        with open(os.path.join(REPO_ROOT, "frontend", "js", "app.js")) as f:
            app_js = f.read()
        test("app.js has RISK_LABELS", "RISK_LABELS" in app_js)
        test("app.js has RECOMMENDATION_LABELS", "RECOMMENDATION_LABELS" in app_js)
        test("app.js has badge-risk class", "badge-risk-" in app_js)

    finally:
        backend_proc.terminate()
        fileserver_proc.terminate()
        try: backend_proc.wait(timeout=5)
        except Exception: backend_proc.kill()
        try: fileserver_proc.wait(timeout=5)
        except Exception: fileserver_proc.kill()

    # Print results
    print("\n" + "=" * 80)
    print("PHASE 6 — SECURITY SCANNER ENGINE TEST RESULTS")
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
