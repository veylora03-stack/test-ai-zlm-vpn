import pytest
from backend.app.services.parser import parse_config, _parse_vless, _parse_hysteria2, _parse_tuic, _parse_wireguard, _parse_openvpn, extract_country_code

class TestCountry:
    def test_de(self): assert extract_country_code("DE-Frankfurt") == "DE"
    def test_us(self): assert extract_country_code("USA-NY") == "US"
    def test_uk(self): assert extract_country_code("UK-London") == "GB"
    def test_unknown(self): assert extract_country_code("Unknown") is None

class TestVless:
    def test_basic(self):
        r = _parse_vless("vless://uuid@ex.com:443#S")
        assert r["protocol"] == "vless" and r["server_host"] == "ex.com"
    def test_reality(self, sample_vless_uri):
        r = _parse_vless(sample_vless_uri)
        assert r["advanced_params"]["security"] == "reality"
    def test_ipv6(self):
        r = _parse_vless("vless://u@[::1]:443#I")
        assert r["server_host"] == "::1"
    def test_invalid(self): assert _parse_vless("vless://invalid") is None

class TestHysteria2:
    def test_basic(self):
        r = _parse_hysteria2("hysteria2://p@ex.com:8443?obfs=salamander#H")
        assert r["protocol"] == "hysteria2" and r["advanced_params"]["obfs"] == "salamander"

class TestTuic:
    def test_basic(self):
        r = _parse_tuic("tuic://u:p@ex.com:443?congestion_control=bbr#T")
        assert r["protocol"] == "tuic" and r["advanced_params"]["congestion_control"] == "bbr"

class TestWG:
    def test_peers(self, sample_wireguard_config):
        r = _parse_wireguard(sample_wireguard_config)
        assert len(r) == 2 and r[0]["server_host"] == "de.ex"

class TestOVPN:
    def test_remote(self, sample_openvpn_config):
        r = _parse_openvpn(sample_openvpn_config)
        assert len(r) == 1 and r[0]["server_host"] == "us.ex"

class TestParseConfig:
    def test_empty(self): assert parse_config("", "m") == []
    def test_mixed(self):
        content = "vless://u@h:443#N1" + chr(10) + "vless://u2@h2:443#N2"
        r = parse_config(content, "m")
        assert len(r) == 2
    def test_malformed(self):
        for i in ["invalid", "vless://bad", "<xml>", ""]:
            assert isinstance(parse_config(i, "m"), list)
