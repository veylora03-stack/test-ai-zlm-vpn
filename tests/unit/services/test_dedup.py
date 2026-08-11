import pytest
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
