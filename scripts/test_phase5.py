"""ERROR-PANEL — Phase 5 integration test script.

Offline-safe tests for the multi-format parser, dedup, and end-to-end sync.
Uses a local http.server to serve sample subscription files.
"""

import base64
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
    # Remove old DB (schema changed — fingerprint column added)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    # ── Build sample files ──────────────────────────────────────────────
    tmpdir = tempfile.mkdtemp(prefix="ep5_test_")

    # 1. WireGuard config with 2 [Peer] sections
    wg_content = """[Interface]
PrivateKey = abc123
Address = 10.0.0.1/24
DNS = 1.1.1.1

# Germany Frankfurt
[Peer]
PublicKey = peerKeyAAA111
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0

# Netherlands Amsterdam
[Peer]
PublicKey = peerKeyBBB222
Endpoint = 5.6.7.8:51821
AllowedIPs = 0.0.0.0/0
"""
    with open(os.path.join(tmpdir, "wg.txt"), "w") as f:
        f.write(wg_content)

    # 2. OpenVPN config with 2 remote lines
    ovpn_content = """client
dev tun
proto udp

# Germany Server
remote 10.20.30.40 1194 udp
remote 10.20.30.41 1195 tcp
resolv-retry infinite
"""
    with open(os.path.join(tmpdir, "ovpn.txt"), "w") as f:
        f.write(ovpn_content)

    # 3. Subscription: one vmess + one vless + one ss URI
    vmess_obj = {
        "ps": "Germany-VMess",
        "add": "11.22.33.44",
        "port": 443,
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "net": "ws",
        "type": "none",
    }
    vmess_b64 = base64.b64encode(json.dumps(vmess_obj).encode()).decode()
    vmess_uri = f"vmess://{vmess_b64}"

    vless_uri = "vless://f1e2d3c4-b5a6-9876-5432-abcdef012345@55.66.77.88:2087?type=ws&security=tls#Netherlands-VLess"

    ss_uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@99.88.77.66:8388#Finland-SS"

    subscription_plain = f"{vmess_uri}\n{vless_uri}\n{ss_uri}\n"
    with open(os.path.join(tmpdir, "sub.txt"), "w") as f:
        f.write(subscription_plain)

    # Also create a base64-encoded version with DIFFERENT URIs (to avoid dedup clash)
    vmess_obj2 = {
        "ps": "Japan-VMess-B64",
        "add": "111.222.33.44",
        "port": 8443,
        "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
        "net": "tcp",
        "type": "none",
    }
    vmess_b64_2 = base64.b64encode(json.dumps(vmess_obj2).encode()).decode()
    vmess_uri2 = f"vmess://{vmess_b64_2}"
    vless_uri2 = "vless://a2b3c4d5-e6f7-8901-2345-bcdef1234567@66.77.88.99:2053?type=ws&security=tls#Sweden-VLess-B64"
    ss_uri2 = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@88.77.66.55:9388#Austria-SS-B64"
    subscription_plain2 = f"{vmess_uri2}\n{vless_uri2}\n{ss_uri2}\n"
    sub_b64 = base64.b64encode(subscription_plain2.encode()).decode()
    with open(os.path.join(tmpdir, "sub_b64.txt"), "w") as f:
        f.write(sub_b64)

    # 4. Trojan URI
    trojan_uri = "trojan://trojan-uuid-1234@77.88.99.110:443?security=tls#Turkey-Trojan"
    with open(os.path.join(tmpdir, "trojan.txt"), "w") as f:
        f.write(trojan_uri + "\n")

    # 5. Malformed garbage
    with open(os.path.join(tmpdir, "garbage.txt"), "w") as f:
        f.write("this is not valid config at all\n<<<>>>{{{{}}\nrandom binary \x00\x01\x02\n")

    # 6. Country extraction test: name containing "Germany"
    wg_germany = """[Interface]
PrivateKey = x
Address = 10.0.0.1/24

# Germany Berlin
[Peer]
PublicKey = germPubKey999
Endpoint = 20.30.40.50:51820
AllowedIPs = 0.0.0.0/0
"""
    with open(os.path.join(tmpdir, "germany.txt"), "w") as f:
        f.write(wg_germany)

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
            urllib.request.urlopen("http://127.0.0.1:8090/wg.txt")
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
        test("Health check", status == 200 and body.get("version") is not None,
             f"status={status}, version={body.get('version') if isinstance(body, dict) else 'N/A'}")

        # ── 2. WireGuard: 2 [Peer] sections → 2 profiles ──────────────
        s_wg, src_wg = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "WG Source", "type": "url",
            "url": "http://127.0.0.1:8090/wg.txt", "status": "pending_review"
        })
        wg_id = src_wg.get("id") if isinstance(src_wg, dict) else None
        sync_s, sync_b = http_request("POST", BACKEND_BASE + f"/api/sources/{wg_id}/sync")
        test("WireGuard sync returns 200", sync_s == 200, f"status={sync_s}")
        test("WireGuard imported_count = 2",
             isinstance(sync_b, dict) and sync_b.get("imported_count") == 2,
             f"got={sync_b.get('imported_count') if isinstance(sync_b, dict) else 'N/A'}")

        # Verify profiles have correct hosts/ports
        ps, plist = http_request("GET", BACKEND_BASE + "/api/profiles/?status=quarantined")
        wg_profiles = [p for p in plist if isinstance(p, dict) and p.get("protocol") == "wireguard"]
        wg_hosts = {p.get("server_host") for p in wg_profiles}
        wg_ports = {p.get("server_port") for p in wg_profiles}
        test("WireGuard hosts correct", "1.2.3.4" in wg_hosts and "5.6.7.8" in wg_hosts,
             f"hosts={wg_hosts}")
        test("WireGuard ports correct", 51820 in wg_ports and 51821 in wg_ports,
             f"ports={wg_ports}")

        # Verify fingerprint is stored
        wg_fps = [p.get("fingerprint") for p in wg_profiles]
        test("WireGuard profiles have fingerprints",
             all(fp is not None and len(fp) == 64 for fp in wg_fps),
             f"fps={[fp[:8] if fp else None for fp in wg_fps]}")

        # Verify fingerprints are different for different public keys
        test("WireGuard fingerprints are different",
             len(set(wg_fps)) == 2, f"unique={len(set(wg_fps))}")

        # ── 3. OpenVPN: 2 remote lines → 2 profiles ───────────────────
        s_ovpn, src_ovpn = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "OVPN Source", "type": "url",
            "url": "http://127.0.0.1:8090/ovpn.txt", "status": "pending_review"
        })
        ovpn_id = src_ovpn.get("id") if isinstance(src_ovpn, dict) else None
        sync_s2, sync_b2 = http_request("POST", BACKEND_BASE + f"/api/sources/{ovpn_id}/sync")
        test("OpenVPN imported_count = 2",
             isinstance(sync_b2, dict) and sync_b2.get("imported_count") == 2,
             f"got={sync_b2.get('imported_count') if isinstance(sync_b2, dict) else 'N/A'}")

        ps2, plist2 = http_request("GET", BACKEND_BASE + "/api/profiles/?status=quarantined")
        ovpn_profiles = [p for p in plist2 if isinstance(p, dict) and p.get("protocol") == "openvpn"]
        ovpn_hosts = {p.get("server_host") for p in ovpn_profiles}
        test("OpenVPN hosts correct",
             "10.20.30.40" in ovpn_hosts and "10.20.30.41" in ovpn_hosts,
             f"hosts={ovpn_hosts}")

        # ── 4. Subscription: vmess + vless + ss → 3 profiles ───────────
        s_sub, src_sub = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Sub Source", "type": "url",
            "url": "http://127.0.0.1:8090/sub.txt", "status": "pending_review"
        })
        sub_id = src_sub.get("id") if isinstance(src_sub, dict) else None
        sync_s3, sync_b3 = http_request("POST", BACKEND_BASE + f"/api/sources/{sub_id}/sync")
        test("Subscription imported_count = 3",
             isinstance(sync_b3, dict) and sync_b3.get("imported_count") == 3,
             f"got={sync_b3.get('imported_count') if isinstance(sync_b3, dict) else 'N/A'}")

        # Verify protocols
        ps3, plist3 = http_request("GET", BACKEND_BASE + "/api/profiles/?status=quarantined")
        sub_profiles = [p for p in plist3 if isinstance(p, dict) and p.get("source_id") == sub_id]
        sub_protocols = {p.get("protocol") for p in sub_profiles}
        test("Subscription has vmess, vless, shadowsocks",
             "vmess" in sub_protocols and "vless" in sub_protocols and "shadowsocks" in sub_protocols,
             f"protocols={sub_protocols}")

        # Verify vmess host/port
        vmess_p = [p for p in sub_profiles if p.get("protocol") == "vmess"]
        test("VMess host correct",
             len(vmess_p) > 0 and vmess_p[0].get("server_host") == "11.22.33.44",
             f"host={vmess_p[0].get('server_host') if vmess_p else 'N/A'}")
        test("VMess port correct",
             len(vmess_p) > 0 and vmess_p[0].get("server_port") == 443,
             f"port={vmess_p[0].get('server_port') if vmess_p else 'N/A'}")

        # Verify vless host/port
        vless_p = [p for p in sub_profiles if p.get("protocol") == "vless"]
        test("VLess host correct",
             len(vless_p) > 0 and vless_p[0].get("server_host") == "55.66.77.88",
             f"host={vless_p[0].get('server_host') if vless_p else 'N/A'}")
        test("VLess port correct",
             len(vless_p) > 0 and vless_p[0].get("server_port") == 2087,
             f"port={vless_p[0].get('server_port') if vless_p else 'N/A'}")

        # Verify ss host/port
        ss_p = [p for p in sub_profiles if p.get("protocol") == "shadowsocks"]
        test("SS host correct",
             len(ss_p) > 0 and ss_p[0].get("server_host") == "99.88.77.66",
             f"host={ss_p[0].get('server_host') if ss_p else 'N/A'}")

        # ── 5. Trojan URI → protocol trojan ────────────────────────────
        s_tr, src_tr = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Trojan Source", "type": "url",
            "url": "http://127.0.0.1:8090/trojan.txt", "status": "pending_review"
        })
        tr_id = src_tr.get("id") if isinstance(src_tr, dict) else None
        sync_s5, sync_b5 = http_request("POST", BACKEND_BASE + f"/api/sources/{tr_id}/sync")
        test("Trojan imported_count = 1",
             isinstance(sync_b5, dict) and sync_b5.get("imported_count") == 1,
             f"got={sync_b5.get('imported_count') if isinstance(sync_b5, dict) else 'N/A'}")

        ps5, plist5 = http_request("GET", BACKEND_BASE + "/api/profiles/?status=quarantined")
        tr_profiles = [p for p in plist5 if isinstance(p, dict) and p.get("source_id") == tr_id]
        test("Trojan protocol is trojan",
             len(tr_profiles) > 0 and tr_profiles[0].get("protocol") == "trojan",
             f"protocol={tr_profiles[0].get('protocol') if tr_profiles else 'N/A'}")
        test("Trojan host/port correct",
             len(tr_profiles) > 0 and tr_profiles[0].get("server_host") == "77.88.99.110"
             and tr_profiles[0].get("server_port") == 443,
             f"host={tr_profiles[0].get('server_host') if tr_profiles else 'N/A'}, "
             f"port={tr_profiles[0].get('server_port') if tr_profiles else 'N/A'}")

        # ── 6. Malformed garbage → returns [] without exception ────────
        s_g, src_g = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Garbage Source", "type": "url",
            "url": "http://127.0.0.1:8090/garbage.txt", "status": "pending_review"
        })
        g_id = src_g.get("id") if isinstance(src_g, dict) else None
        sync_sg, sync_bg = http_request("POST", BACKEND_BASE + f"/api/sources/{g_id}/sync")
        test("Malformed content: sync succeeds with 0 imports",
             sync_sg == 200 and isinstance(sync_bg, dict) and sync_bg.get("imported_count") == 0,
             f"status={sync_sg}, imported={sync_bg.get('imported_count') if isinstance(sync_bg, dict) else 'N/A'}")

        # ── 7. Country extraction: name containing "Germany" → DE ──────
        s_de, src_de = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "Germany Source", "type": "url",
            "url": "http://127.0.0.1:8090/germany.txt", "status": "pending_review"
        })
        de_id = src_de.get("id") if isinstance(src_de, dict) else None
        sync_sde, _ = http_request("POST", BACKEND_BASE + f"/api/sources/{de_id}/sync")
        ps_de, plist_de = http_request("GET", BACKEND_BASE + "/api/profiles/?status=quarantined")
        de_profiles = [p for p in plist_de if isinstance(p, dict) and p.get("source_id") == de_id]
        test("Country extraction: Germany → DE",
             len(de_profiles) > 0 and de_profiles[0].get("country_code") == "DE",
             f"cc={de_profiles[0].get('country_code') if de_profiles else 'N/A'}")

        # ── 8. End-to-end: sync subscription → imported=3; sync again → imported=0, duplicates=3
        # (The sub source was already synced in test 4)
        sync_s3b, sync_b3b = http_request("POST", BACKEND_BASE + f"/api/sources/{sub_id}/sync")
        test("Re-sync: imported_count = 0",
             isinstance(sync_b3b, dict) and sync_b3b.get("imported_count") == 0,
             f"got={sync_b3b.get('imported_count') if isinstance(sync_b3b, dict) else 'N/A'}")
        test("Re-sync: duplicates = 3",
             isinstance(sync_b3b, dict) and sync_b3b.get("duplicates") == 3,
             f"got={sync_b3b.get('duplicates') if isinstance(sync_b3b, dict) else 'N/A'}")

        # Verify profiles table has only 3 rows for that source
        ps_check, plist_check = http_request("GET", BACKEND_BASE + "/api/profiles/")
        source_profiles = [p for p in plist_check if isinstance(p, dict) and p.get("source_id") == sub_id]
        test("Source has exactly 3 profiles after re-sync",
             len(source_profiles) == 3, f"count={len(source_profiles)}")

        # ── 9. Verify quarantined status on all imported profiles ───────
        all_quarantined = all(
            p.get("status") == "quarantined"
            for p in source_profiles
        )
        test("All imported profiles have quarantined status", all_quarantined)

        # Verify fingerprint stored
        all_have_fp = all(
            p.get("fingerprint") is not None and len(p.get("fingerprint", "")) == 64
            for p in source_profiles
        )
        test("All imported profiles have fingerprint", all_have_fp)

        # ── 10. Base64 subscription blob ───────────────────────────────
        s_b64, src_b64 = http_request("POST", BACKEND_BASE + "/api/sources/", {
            "name": "B64 Sub Source", "type": "url",
            "url": "http://127.0.0.1:8090/sub_b64.txt", "status": "pending_review"
        })
        b64_id = src_b64.get("id") if isinstance(src_b64, dict) else None
        sync_b64s, sync_b64b = http_request("POST", BACKEND_BASE + f"/api/sources/{b64_id}/sync")
        test("Base64 subscription: imported_count = 3",
             isinstance(sync_b64b, dict) and sync_b64b.get("imported_count") == 3,
             f"got={sync_b64b.get('imported_count') if isinstance(sync_b64b, dict) else 'N/A'}")

        # ── 11. Audit logs ──────────────────────────────────────────────
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT action, entity_type, details_json FROM audit_logs WHERE action='sync' ORDER BY id"
            ).fetchall()
            conn.close()

            # Check that sync audit logs contain imported_count and duplicates
            has_dedup_in_audit = False
            for r in rows:
                try:
                    det = json.loads(r[2]) if r[2] else {}
                    if "duplicates" in det:
                        has_dedup_in_audit = True
                        break
                except Exception:
                    pass
            test("Audit log sync entries contain duplicates field", has_dedup_in_audit)
        else:
            test("Audit log check", False, "DB not found")

        # ── 12. Frontend JS syntax check ───────────────────────────────
        js_check_api = subprocess.run(
            ["node", "--check", os.path.join(REPO_ROOT, "frontend", "js", "api.js")],
            capture_output=True, text=True
        )
        test("node --check api.js", js_check_api.returncode == 0,
             js_check_api.stderr.strip() if js_check_api.returncode != 0 else "OK")

        js_check_app = subprocess.run(
            ["node", "--check", os.path.join(REPO_ROOT, "frontend", "js", "app.js")],
            capture_output=True, text=True
        )
        test("node --check app.js", js_check_app.returncode == 0,
             js_check_app.stderr.strip() if js_check_app.returncode != 0 else "OK")

        # ── 13. Frontend sync toast shows duplicates ──────────────────
        with open(os.path.join(REPO_ROOT, "frontend", "js", "app.js")) as f:
            app_js = f.read()
        test("app.js sync toast shows duplicates count",
             "duplicates" in app_js and "تکراری" in app_js)

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
    print("PHASE 5 — CONFIG PARSER ENGINE & DEDUPLICATION TEST RESULTS")
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
