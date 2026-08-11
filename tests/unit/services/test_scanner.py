import pytest
from unittest.mock import MagicMock
from backend.app.services.scanner import _check_private_key_exposed, _check_exec_directives, _check_weak_cipher, _check_http_endpoint, _check_localhost_or_private, _is_private_ip, _is_suspicious_port

class TestPrivateIP:
    def test_local(self): assert _is_private_ip("127.0.0.1") and _is_private_ip("localhost")
    def test_private(self): assert _is_private_ip("10.0.0.1") and _is_private_ip("192.168.1.1")
    def test_public(self): assert not _is_private_ip("8.8.8.8")

class TestSuspPort:
    def test_suspicious(self): assert _is_suspicious_port(23) and _is_suspicious_port(3389)
    def test_normal(self): assert not _is_suspicious_port(443)

class TestPrivKey:
    def test_wg(self):
        config = "[Interface]" + chr(10) + "PrivateKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        r = _check_private_key_exposed(config, "wireguard")
        assert r["code"] == "private_key_exposed"
    def test_rsa(self):
        config = "-----BEGIN RSA PRIVATE KEY-----" + chr(10) + "test" + chr(10) + "-----END RSA PRIVATE KEY-----"
        r = _check_private_key_exposed(config, "openvpn")
        assert r["code"] == "private_key_exposed"

class TestExec:
    def test_ovpn(self, insecure_openvpn_config):
        assert _check_exec_directives(insecure_openvpn_config, "openvpn")["code"] == "exec_directives"
    def test_not_ovpn(self): assert _check_exec_directives("up /s.sh", "wireguard") is None

class TestWeakCipher:
    def test_des(self, sample_openvpn_config):
        r = _check_weak_cipher(sample_openvpn_config, "openvpn")
        assert r["code"] == "weak_cipher" and "DES" in r["message"]

class TestHTTP:
    def test_detected(self):
        assert _check_http_endpoint("remote http://ex.com/path", "openvpn")["code"] == "http_endpoint"
    def test_comment(self):
        config = "# Visit http://ex.com" + chr(10) + "remote ex.com"
        assert _check_http_endpoint(config, "openvpn") is None

class TestLocalhostProf:
    def test_local(self):
        p = MagicMock(server_host="127.0.0.1")
        assert _check_localhost_or_private(p)["code"] == "localhost_or_private_remote"
