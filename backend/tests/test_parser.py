"""Tests for enhanced parser service."""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.parser import (
    parse_config,
    _parse_vless,
    _parse_vmess,
    _parse_hysteria2,
    _parse_tuic,
    extract_country_code,
)

def test_extract_country_code():
    """Test country code extraction."""
    assert extract_country_code("Germany-Frankfurt") == "DE"
    assert extract_country_code("USA-NewYork") == "US"
    assert extract_country_code("UK-London") == "GB"
    assert extract_country_code("Unknown-Server") is None
    print("✓ test_extract_country_code passed")

def test_parse_vless_reality():
    """Test VLess with Reality protocol."""
    uri = "vless://uuid123@server.example.com:443?security=reality&sni=example.com&pbk=publickey123&type=tcp&flow=xtls-rprx-vision#Reality-DE"
    result = _parse_vless(uri)
    
    assert result is not None
    assert result["protocol"] == "vless"
    assert result["server_host"] == "server.example.com"
    assert result["server_port"] == 443
    assert result["country_code"] == "DE"
    assert result["advanced_params"]["security"] == "reality"
    assert result["advanced_params"]["publicKey"] == "publickey123"
    assert result["advanced_params"]["sni"] == "example.com"
    print("✓ test_parse_vless_reality passed")

def test_parse_hysteria2():
    """Test Hysteria2 protocol."""
    uri = "hysteria2://password123@server.example.com:8443?sni=example.com&obfs=salamander#Hysteria-US"
    result = _parse_hysteria2(uri)
    
    assert result is not None
    assert result["protocol"] == "hysteria2"
    assert result["server_host"] == "server.example.com"
    assert result["server_port"] == 8443
    assert result["country_code"] == "US"
    assert result["advanced_params"]["obfs"] == "salamander"
    print("✓ test_parse_hysteria2 passed")

def test_parse_tuic():
    """Test TUIC protocol."""
    uri = "tuic://uuid123:password123@server.example.com:443?sni=example.com&congestion_control=bbr#TUIC-JP"
    result = _parse_tuic(uri)
    
    assert result is not None
    assert result["protocol"] == "tuic"
    assert result["server_host"] == "server.example.com"
    assert result["server_port"] == 443
    assert result["country_code"] == "JP"
    assert result["advanced_params"]["congestion_control"] == "bbr"
    print("✓ test_parse_tuic passed")

def test_parse_config_multiple():
    """Test parsing multiple protocols."""
    content = """
vless://uuid1@server1.com:443?security=reality&sni=example.com#Server1
vmess://eyJhZGQiOiJzZXJ2ZXIyLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6InV1aWQyIiwicHMiOiJTZXJ2ZXIyIn0=
hysteria2://pass@server3.com:8443#Server3
"""
    results = parse_config(content, "manual")
    
    assert len(results) == 3
    assert results[0]["protocol"] == "vless"
    assert results[1]["protocol"] == "vmess"
    assert results[2]["protocol"] == "hysteria2"
    print("✓ test_parse_config_multiple passed")

if __name__ == "__main__":
    print("Running parser tests...\n")
    
    try:
        test_extract_country_code()
        test_parse_vless_reality()
        test_parse_hysteria2()
        test_parse_tuic()
        test_parse_config_multiple()
        
        print("\n" + "="*50)
        print("All tests passed! ✓")
        print("="*50)
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
