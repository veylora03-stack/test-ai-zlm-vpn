import asyncio, os, pytest, pytest_asyncio
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
    return """[Interface]
PrivateKey=test

[Peer]
#DE
PublicKey=k1
Endpoint=de.ex:51820
AllowedIPs=0.0.0.0/0

[Peer]
#US
PublicKey=k2
Endpoint=us.ex:51820"""

@pytest.fixture
def sample_openvpn_config():
    return """client
dev tun
proto udp
remote us.ex 1194
cipher DES"""

@pytest.fixture
def insecure_openvpn_config():
    return """client
up /s.sh
down /s.sh
plugin /p.so
script-security 3"""
