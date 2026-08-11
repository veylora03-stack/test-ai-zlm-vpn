"""ERROR-PANEL — Phase 7 integration test script.

Offline-safe tests for network tester, ranking engine, analytics,
and regression of earlier phases.
"""

import asyncio
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

    tmpdir = tempfile.mkdtemp(prefix="ep7_test_")

    # Create a simple file for the local http.server (just needs to listen on 8090)
    with open(os.path.join(tmpdir, "index.html"), "w") as f:
        f.write("<html><body>OK</body></html>")

    # Start local file server on 8090 (for tester to connect to)
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
            urllib.request.urlopen("http://127.0.0.1:8090/index.html")
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
        test("Health check version", status == 200 and body.get("version") is not None,
             f"version={body.get('version') if isinstance(body, dict) else 'N/A'}")

        # ── 2. Create approved profile pointing to 127.0.0.1:8090 ─────
        s1, p1 = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "name": "Test-Reachable", "protocol": "wireguard",
            "server_host": "127.0.0.1", "server_port": 8090,
            "status": "approved"
        })
        p1_id = p1.get("id") if isinstance(p1, dict) else None
        test("Create reachable profile", p1_id is not None, f"id={p1_id}")

        # ── 3. Run test on reachable profile ───────────────────────────
        ts, tb = http_request("POST", BACKEND_BASE + f"/api/tests/run/{p1_id}")
        test("POST /api/tests/run/{id} -> 200", ts == 200,
             f"status={ts}, body={tb}")
        if ts == 200 and isinstance(tb, dict):
            test("Reachable: ping_ms not null (implies reachable)", tb.get("ping_ms") is not None,
                 f"ping_ms={tb.get('ping_ms')}")
            test("Reachable: packet_loss_pct = 0", tb.get("packet_loss_pct") == 0.0,
                 f"packet_loss_pct={tb.get('packet_loss_pct')}")
            test("Reachable: error_message is null", tb.get("error_message") is None,
                 f"error_message={tb.get('error_message')}")
        else:
            test("Reachable: ping_ms not null (implies reachable)", False, "test failed")
            test("Reachable: packet_loss_pct = 0", False, "test failed")
            test("Reachable: error_message is null", False, "test failed")

        # ── 4. Verify Metric row persisted ─────────────────────────────
        ms, mb = http_request("GET", BACKEND_BASE + f"/api/metrics?profile_id={p1_id}")
        test("GET /api/metrics returns stored rows",
             ms == 200 and isinstance(mb, list) and len(mb) >= 1,
             f"status={ms}, count={len(mb) if isinstance(mb, list) else 'N/A'}")

        # ── 5. Create profile pointing to 127.0.0.1:8099 (nothing) ────
        s2, p2 = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "name": "Test-Unreachable", "protocol": "wireguard",
            "server_host": "127.0.0.1", "server_port": 8099,
            "status": "approved"
        })
        p2_id = p2.get("id") if isinstance(p2, dict) else None

        ts2, tb2 = http_request("POST", BACKEND_BASE + f"/api/tests/run/{p2_id}")
        test("Unreachable test returns 200", ts2 == 200, f"status={ts2}")
        if ts2 == 200 and isinstance(tb2, dict):
            test("Unreachable: packet_loss_pct = 100 (implies unreachable)", tb2.get("packet_loss_pct") == 100.0,
                 f"packet_loss_pct={tb2.get('packet_loss_pct')}")
            test("Unreachable: error_message not null", tb2.get("error_message") is not None,
                 f"error_message={tb2.get('error_message')}")
            test("Unreachable: ping_ms is null", tb2.get("ping_ms") is None,
                 f"ping_ms={tb2.get('ping_ms')}")
        else:
            test("Unreachable: packet_loss_pct = 100 (implies unreachable)", False, "test failed")
            test("Unreachable: error_message not null", False, "test failed")
            test("Unreachable: ping_ms is null", False, "test failed")

        # ── 6. GET /api/metrics for unreachable profile ────────────────
        ms2, mb2 = http_request("GET", BACKEND_BASE + f"/api/metrics?profile_id={p2_id}")
        test("Unreachable profile has metric history",
             ms2 == 200 and isinstance(mb2, list) and len(mb2) >= 1,
             f"count={len(mb2) if isinstance(mb2, list) else 'N/A'}")

        # ── 7. POST /api/metrics manual speed submission ───────────────
        sm, mm = http_request("POST", BACKEND_BASE + "/api/metrics", {
            "profile_id": p1_id,
            "download_mbps": 120.5,
            "upload_mbps": 40.0,
            "ping_ms": 15.0
        })
        test("Manual metric submission -> 201", sm == 201,
             f"status={sm}, body={mm}")
        test("Manual metric download_mbps = 120.5",
             isinstance(mm, dict) and mm.get("download_mbps") == 120.5,
             f"dl={mm.get('download_mbps') if isinstance(mm, dict) else 'N/A'}")
        test("Manual metric upload_mbps = 40.0",
             isinstance(mm, dict) and mm.get("upload_mbps") == 40.0,
             f"ul={mm.get('upload_mbps') if isinstance(mm, dict) else 'N/A'}")

        # ── 8. Verify manual metric in history ─────────────────────────
        ms3, mb3 = http_request("GET", BACKEND_BASE + f"/api/metrics?profile_id={p1_id}")
        has_manual = False
        if isinstance(mb3, list):
            for m in mb3:
                if isinstance(m, dict) and m.get("download_mbps") == 120.5:
                    has_manual = True
                    break
        test("Manual metric visible in history", has_manual)

        # ── 9. Seed profiles for ranking ───────────────────────────────
        # Create 3 approved profiles with distinct metrics + 1 quarantined with best ping

        # Profile A: approved, good metrics
        sa, pa = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "name": "Rank-A", "protocol": "wireguard",
            "server_host": "10.0.0.1", "server_port": 51820,
            "status": "approved", "risk_score": 10
        })
        pa_id = pa["id"] if isinstance(pa, dict) else None

        # Profile B: approved, medium metrics
        sb, pb = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "name": "Rank-B", "protocol": "openvpn",
            "server_host": "10.0.0.2", "server_port": 1194,
            "status": "approved", "risk_score": 30
        })
        pb_id = pb["id"] if isinstance(pb, dict) else None

        # Profile C: approved, bad metrics
        sc, pc = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "name": "Rank-C", "protocol": "vless",
            "server_host": "10.0.0.3", "server_port": 443,
            "status": "approved", "risk_score": 80
        })
        pc_id = pc["id"] if isinstance(pc, dict) else None

        # Profile Q: quarantined with best ping (should be excluded from ranking)
        sq, pq = http_request("POST", BACKEND_BASE + "/api/profiles/", {
            "name": "Rank-Q-Quarantined", "protocol": "vmess",
            "server_host": "10.0.0.4", "server_port": 443,
            "status": "quarantined", "risk_score": 5
        })
        pq_id = pq["id"] if isinstance(pq, dict) else None

        # Submit manual metrics for each
        # A: dl=180, ul=80, ping=20, loss=0, jitter=2 → very good
        http_request("POST", BACKEND_BASE + "/api/metrics", {
            "profile_id": pa_id, "download_mbps": 180, "upload_mbps": 80, "ping_ms": 20
        })
        # B: dl=100, ul=50, ping=50, loss=0, jitter=5 → medium
        http_request("POST", BACKEND_BASE + "/api/metrics", {
            "profile_id": pb_id, "download_mbps": 100, "upload_mbps": 50, "ping_ms": 50
        })
        # C: dl=30, ul=10, ping=200, loss=5, jitter=30 → poor
        http_request("POST", BACKEND_BASE + "/api/metrics", {
            "profile_id": pc_id, "download_mbps": 30, "upload_mbps": 10, "ping_ms": 200
        })
        # Q: best ping but quarantined → excluded
        http_request("POST", BACKEND_BASE + "/api/metrics", {
            "profile_id": pq_id, "download_mbps": 200, "upload_mbps": 100, "ping_ms": 5
        })

        # Also add a test-derived metric for A with loss/jitter info
        # (use the tester to generate a metric with loss and jitter)
        # For ranking, we use the LATEST metric per profile.
        # Let's add a second metric for C that includes packet loss
        # We'll use the test endpoint on 127.0.0.1:8099 for C to get loss data
        # Actually, let's just add manual metrics with more data.
        # The manual metric endpoint sets loss=0, jitter=0 by default.
        # To test jitter/loss in ranking, we need to use the test endpoint.
        # But for now, the manual metrics are sufficient to test the ranking formula.

        # ── 10. GET /api/ranking/top?metric=ping ───────────────────────
        rp_s, rp_b = http_request("GET", BACKEND_BASE + "/api/ranking/top?metric=ping&limit=10")
        test("Ranking ping returns 200", rp_s == 200, f"status={rp_s}")

        # Check ascending order (lower ping first)
        if isinstance(rp_b, list) and len(rp_b) >= 3:
            pings = [r.get("ping_ms") for r in rp_b if r.get("ping_ms") is not None]
            ascending = all(pings[i] <= pings[i + 1] for i in range(len(pings) - 1))
            test("Ping ranking: ascending order", ascending, f"pings={pings}")

            # Quarantined profile should be excluded
            ranked_ids = [r.get("id") for r in rp_b]
            test("Ping ranking: excludes quarantined", pq_id not in ranked_ids,
                 f"ids={ranked_ids}, quarantined_id={pq_id}")
        else:
            test("Ping ranking: ascending order", False, f"body={rp_b}")
            test("Ping ranking: excludes quarantined", False, "not enough results")

        # ── 11. GET /api/ranking/top?metric=score ──────────────────────
        rs_s, rs_b = http_request("GET", BACKEND_BASE + "/api/ranking/top?metric=score&limit=10")
        test("Ranking score returns 200", rs_s == 200, f"status={rs_s}")

        if isinstance(rs_b, list) and len(rs_b) >= 3:
            # Hand-compute expected scores:
            # A: dl_norm=min(180/200,1)=0.9, ul_norm=min(80/100,1)=0.8,
            #    ping_norm=max(0,1-20/1000)=0.98, stab=(1-0/100)*(1-min(0/200,1))=1,
            #    sec=1-10/100=0.9
            #    score=0.35*0.9+0.20*0.8+0.20*0.98+0.15*1+0.10*0.9
            #         =0.315+0.16+0.196+0.15+0.09 = 0.911
            # B: dl_norm=0.5, ul_norm=0.5, ping_norm=0.95, stab=1, sec=0.7
            #    score=0.35*0.5+0.20*0.5+0.20*0.95+0.15*1+0.10*0.7
            #         =0.175+0.10+0.19+0.15+0.07 = 0.685
            # C: dl_norm=0.15, ul_norm=0.1, ping_norm=0.8, stab=1, sec=0.2
            #    score=0.35*0.15+0.20*0.1+0.20*0.8+0.15*1+0.10*0.2
            #         =0.0525+0.02+0.16+0.15+0.02 = 0.4025

            # Order should be A > B > C (descending)
            ranked_names = [r.get("name") for r in rs_b]
            a_idx = ranked_names.index("Rank-A") if "Rank-A" in ranked_names else -1
            b_idx = ranked_names.index("Rank-B") if "Rank-B" in ranked_names else -1
            c_idx = ranked_names.index("Rank-C") if "Rank-C" in ranked_names else -1

            test("Score ranking: A > B > C",
                 a_idx < b_idx < c_idx if a_idx >= 0 and b_idx >= 0 and c_idx >= 0 else False,
                 f"names={ranked_names}, a_idx={a_idx}, b_idx={b_idx}, c_idx={c_idx}")

            # Verify score values approximately match hand computation
            a_entry = next((r for r in rs_b if r.get("name") == "Rank-A"), None)
            if a_entry:
                score_a = a_entry.get("score", 0)
                test("Score A ≈ 0.911", abs(score_a - 0.911) < 0.01,
                     f"score_a={score_a}")
            else:
                test("Score A ≈ 0.911", False, "A not found in ranking")

            # Quarantined excluded from score ranking too
            ranked_ids_score = [r.get("id") for r in rs_b]
            test("Score ranking: excludes quarantined", pq_id not in ranked_ids_score,
                 f"ids={ranked_ids_score}")
        else:
            test("Score ranking: A > B > C", False, "not enough results")
            test("Score A ≈ 0.911", False, "not enough results")
            test("Score ranking: excludes quarantined", False, "not enough results")

        # ── 12. GET /api/analytics/overview ─────────────────────────────
        ao_s, ao_b = http_request("GET", BACKEND_BASE + "/api/analytics/overview")
        test("Analytics overview returns 200", ao_s == 200, f"status={ao_s}")

        if ao_s == 200 and isinstance(ao_b, dict):
            counts_status = ao_b.get("counts_by_status", {})
            counts_proto = ao_b.get("counts_by_protocol", {})

            # We created: 2 approved (p1, reachable) + 3 approved (A, B, C) + 1 quarantined (Q)
            # Plus the unreachable profile is also approved
            # So approved count should be at least 5
            approved_count = counts_status.get("approved", 0)
            quarantined_count_analytics = counts_status.get("quarantined", 0)
            test("Analytics: approved count >= 5", approved_count >= 5,
                 f"approved={approved_count}")
            test("Analytics: quarantined count >= 1", quarantined_count_analytics >= 1,
                 f"quarantined={quarantined_count_analytics}")

            # Protocol counts should include wireguard, openvpn, vless, vmess
            test("Analytics: protocol counts has wireguard", "wireguard" in counts_proto,
                 f"protocols={list(counts_proto.keys())}")

            # Sources total should be >= 0
            test("Analytics: sources_total >= 0", ao_b.get("sources_total", -1) >= 0,
                 f"sources_total={ao_b.get('sources_total')}")

            # Ping trend should be a list
            ping_trend = ao_b.get("ping_trend", [])
            test("Analytics: ping_trend is list", isinstance(ping_trend, list),
                 f"type={type(ping_trend).__name__}")
        else:
            test("Analytics: approved count >= 5", False, "overview failed")
            test("Analytics: quarantined count >= 1", False, "overview failed")
            test("Analytics: protocol counts has wireguard", False, "overview failed")
            test("Analytics: sources_total >= 0", False, "overview failed")
            test("Analytics: ping_trend is list", False, "overview failed")

        # ── 13. Frontend checks ─────────────────────────────────────────
        with open(os.path.join(REPO_ROOT, "frontend", "js", "app.js")) as f:
            app_js = f.read()
        test("app.js contains runTest", "runTest" in app_js or "runTestAction" in app_js)
        test("app.js contains getRanking", "getRanking" in app_js)
        test("app.js contains getAnalytics", "getAnalytics" in app_js)

        with open(os.path.join(REPO_ROOT, "frontend", "js", "api.js")) as f:
            api_js = f.read()
        test("api.js contains runTest", "async function runTest" in api_js)
        test("api.js contains getMetrics", "async function getMetrics" in api_js)
        test("api.js contains submitMetrics", "async function submitMetrics" in api_js)
        test("api.js contains getRanking", "async function getRanking" in api_js)
        test("api.js contains getAnalytics", "async function getAnalytics" in api_js)

        # Check index.html: Analytics section no longer says فاز ۷
        with open(os.path.join(REPO_ROOT, "frontend", "index.html")) as f:
            html = f.read()
        test("index.html Analytics section no longer says فاز ۷",
             "فاز ۷" not in html and "فاز\\u200f۷" not in html,
             "Found فاز ۷ placeholder still in HTML")

        # ── 14. JS syntax check ─────────────────────────────────────────
        for jsf in ["api.js", "app.js"]:
            r = subprocess.run(
                ["node", "--check", os.path.join(REPO_ROOT, "frontend", "js", jsf)],
                capture_output=True, text=True
            )
            test(f"node --check {jsf}", r.returncode == 0,
                 r.stderr.strip() if r.returncode != 0 else "OK")

        # ── 15. Audit log has test and metric_manual entries ───────────
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT action FROM audit_logs"
            ).fetchall()
            actions = [r[0] for r in rows]
            conn.close()
            test("Audit log has 'test' entry", "test" in actions, f"actions={set(actions)}")
            test("Audit log has 'metric_manual' entry", "metric_manual" in actions,
                 f"actions={set(actions)}")
        else:
            test("Audit log has 'test' entry", False, "DB not found")
            test("Audit log has 'metric_manual' entry", False, "DB not found")

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
    print("PHASE 7 — NETWORK TESTER, RANKING ENGINE & ANALYTICS TEST RESULTS")
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
