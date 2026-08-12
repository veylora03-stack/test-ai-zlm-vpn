"""
Unit tests for the security scanner service.
"""
import pytest
from backend.app.services.scanner import (
    _check_weak_tls_version,
    _check_missing_tls_auth,
    _check_no_tls_verify,
    _check_weak_cipher
)

class TestOpenVPNScanner:
    """Tests specific to OpenVPN security checks."""

    def test_weak_tls_version_1_0(self):
        text = "tls-version-min 1.0"
        result = _check_weak_tls_version(text, "openvpn")
        assert result is not None
        assert result["code"] == "weak_tls_version"

    def test_weak_tls_version_1_1(self):
        text = "tls-version-min 1.1"
        result = _check_weak_tls_version(text, "openvpn")
        assert result is not None
        assert result["code"] == "weak_tls_version"

    def test_strong_tls_version_1_2(self):
        text = "tls-version-min 1.2"
        result = _check_weak_tls_version(text, "openvpn")
        assert result is None

    def test_missing_tls_auth_and_crypt(self):
        text = "client\nremote 1.2.3.4 443"
        result = _check_missing_tls_auth(text, "openvpn")
        assert result is not None
        assert result["code"] == "missing_tls_auth"

    def test_present_tls_auth(self):
        text = "client\nremote 1.2.3.4 443\ntls-auth ta.key 1"
        result = _check_missing_tls_auth(text, "openvpn")
        assert result is None

    def test_present_tls_crypt(self):
        text = "client\nremote 1.2.3.4 443\ntls-crypt tc.key"
        result = _check_missing_tls_auth(text, "openvpn")
        assert result is None

    def test_no_tls_verify_missing_ca(self, mock_raw_text):
        # Remove <ca> block
        text = mock_raw_text.replace("<ca>\n-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n</ca>\n", "")
        result = _check_no_tls_verify(text, "openvpn")
        assert result is not None
        assert result["code"] == "no_tls_verify"
        assert "missing CA" in result["message"]

    def test_weak_cipher_des(self):
        text = "cipher DES"
        result = _check_weak_cipher(text, "openvpn")
        assert result is not None
        assert result["code"] == "weak_cipher"
