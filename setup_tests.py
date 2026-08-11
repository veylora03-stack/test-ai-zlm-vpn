import os
from pathlib import Path

def create_file(path, content):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Created: {path}")

for d in ['tests', 'tests/unit', 'tests/unit/services', 'tests/integration', 'tests/integration/api']:
    Path(d).mkdir(parents=True, exist_ok=True)
    init_path = Path(d) / '__init__.py'
    if not init_path.exists():
        init_path.touch()

# conftest.py
create_file('tests/conftest.py', '''import asyncio, os, pytest, pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
os.environ["TESTING"] = "1"

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest_asyncio.fixture
async def test_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    from backend.app.db import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()

@pytest_asyncio.fixture
async def sample_source(test_db):
    from backend.app.models import Source
    s = Source(name="Test", type="github", url="https://test.com", status="active", reputation_score=75)
    test_db.add(s)
    await test_db.commit()
    await test_db.refresh(s)
    return s

@pytest_asyncio.fixture
async def sample_profile(test_db, sample_source):
    from backend.app.models import Profile
    p = Profile(source_id=sample_source.id, name="Test", protocol="vless", server_host="example.com", server_port=443, country_code="US", status="quarantined", risk_score=0, fingerprint="abc123")
    test_db.add(p)
    await test_db.commit()
    await test_db.refresh(p)
    return p

@pytest.fixture
def sample_vless_uri():
    return "vless://test@example.com:443?security=reality&sni=example.com&pbk=test-pbk&type=tcp#US"

@pytest.fixture
def sample_wireguard_config():
    return """[Interface]\nPrivateKey=test\n\n[Peer]\n#DE\nPublicKey=k1\nEndpoint=de.ex:51820\nAllowedIPs=0.0.0.0/0\n\n[Peer]\n#US\nPublicKey=k2\nEndpoint=us.ex:51820"""

@pytest.fixture
def sample_openvpn_config():
    return "client\ndev tun\nproto udp\nremote us.ex 1194\ncipher DES\n"

@pytest.fixture
def insecure_openvpn_config():
    return "client\nup /s.sh\ndown /s.sh\nplugin /p.so\nscript-security 3\n"
''')

# test_parser.py
create_file('tests/unit/services/test_parser.py', '''import pytest
from backend.app.services.parser import parse_config, _parse_vless, _parse_hysteria2, _parse_tuic, _parse_wireguard, _parse_openvpn, extract_country_code

class TestCountry:
    def test_de(self): assert extract_country_code("DE-Frankfurt") == "DE"
    def test_us(self): assert extract_country_code("US-NY") == "US"
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
        r = parse_config("vless://u@h:443#N1\\nvless://u2@h2:443#N2", "m")
        assert len(r) == 2
    def test_malformed(self):
        for i in ["invalid", "vless://bad", "<xml>", ""]:
            assert isinstance(parse_config(i, "m"), list)
''')

# test_scanner.py
create_file('tests/unit/services/test_scanner.py', '''import pytest
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
        r = _check_private_key_exposed("[Interface]\\nPrivateKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "wireguard")
        assert r["code"] == "private_key_exposed"
    def test_rsa(self):
        r = _check_private_key_exposed("-----BEGIN RSA PRIVATE KEY-----\\ntest\\n-----END RSA PRIVATE KEY-----", "openvpn")
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
        assert _check_http_endpoint("# Visit http://ex.com\\nremote ex.com", "openvpn") is None

class TestLocalhostProf:
    def test_local(self):
        p = MagicMock(server_host="127.0.0.1")
        assert _check_localhost_or_private(p)["code"] == "localhost_or_private_remote"
''')

# test_dedup.py
create_file('tests/unit/services/test_dedup.py', '''import pytest
from backend.app.services.dedup import fingerprint, find_duplicate

class TestFingerprint:
    def test_basic(self):
        c = {"protocol":"vless","server_host":"ex.com","server_port":443,"fingerprint_data":{"uuid":"t"}}
        assert len(fingerprint(c)) == 64
    def test_stable(self):
        c = {"protocol":"vless","server_host":"ex.com","server_port":443,"fingerprint_data":{"uuid":"t"}}
        assert fingerprint(c) == fingerprint(c)
    def test_case(self):
        c1 = {"protocol":"VLESS","server_host":"EX.COM","server_port":443,"fingerprint_data":{"uuid":"T"}}
        c2 = {"protocol":"vless","server_host":"ex.com","server_port":443,"fingerprint_data":{"uuid":"t"}}
        assert fingerprint(c1) == fingerprint(c2)
    def test_diff(self):
        c1 = {"protocol":"vless","server_host":"h1.com","server_port":443,"fingerprint_data":{"uuid":"u1"}}
        c2 = {"protocol":"vless","server_host":"h2.com","server_port":443,"fingerprint_data":{"uuid":"u2"}}
        assert fingerprint(c1) != fingerprint(c2)

class TestFindDup:
    @pytest.mark.asyncio
    async def test_found(self, test_db, sample_profile):
        r = await find_duplicate(test_db, sample_profile.fingerprint)
        assert r.id == sample_profile.id
    @pytest.mark.asyncio
    async def test_not_found(self, test_db):
        assert await find_duplicate(test_db, "non-existent") is None
''')

# test_fetcher.py
create_file('tests/unit/services/test_fetcher.py', '''import pytest
from unittest.mock import patch, MagicMock
from backend.app.services.fetcher import fetch_source, SchemeError, SizeError, MAX_BODY_BYTES

class TestFetch:
    @pytest.mark.asyncio
    async def test_invalid_scheme(self):
        with pytest.raises(SchemeError): await fetch_source("ftp://ex.com")
        with pytest.raises(SchemeError): await fetch_source("file:///etc/passwd")
    @pytest.mark.asyncio
    async def test_valid_http(self):
        with patch('backend.app.services.fetcher.httpx.AsyncClient') as m:
            r = MagicMock()
            r.url.scheme = "http"
            r.raise_for_status = MagicMock()
            async def mock_bytes(chunk_size): yield b"test"
            r.aiter_bytes = mock_bytes
            m.return_value.__aenter__.return_value.stream.return_value.__aenter__.return_value = r
            res = await fetch_source("http://ex.com")
            assert res["content"] == "test"
    @pytest.mark.asyncio
    async def test_size_limit(self):
        with patch('backend.app.services.fetcher.httpx.AsyncClient') as m:
            r = MagicMock()
            r.url.scheme = "https"
            r.raise_for_status = MagicMock()
            async def mock_bytes(chunk_size): yield b"x" * (MAX_BODY_BYTES + 1)
            r.aiter_bytes = mock_bytes
            m.return_value.__aenter__.return_value.stream.return_value.__aenter__.return_value = r
            with pytest.raises(SizeError): await fetch_source("https://ex.com/large")
''')

# pytest.ini
create_file('pytest.ini', '''[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
addopts = -v --tb=short --cov=backend --cov-report=term-missing --cov-report=html:htmlcov
filterwarnings = ignore::DeprecationWarning
markers = slow: slow tests, integration: integration tests
''')

print("\\n✅ All test files created!")
print("Next: Run 'python setup_ci.py' for GitHub Actions")
