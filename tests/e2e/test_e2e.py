"""
تست End-to-End با httpx.AsyncClient و base_url=localhost
"""

import pytest
import pytest_asyncio
import httpx
import sys
import os

# اضافه کردن مسیر پروژه به sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

BASE_URL = "http://127.0.0.1:8000"

@pytest_asyncio.fixture
async def client():
    """Create HTTP client that bypasses proxy settings"""
    async with httpx.AsyncClient(
        base_url=BASE_URL,
        trust_env=False,  # Ignore HTTP_PROXY/HTTPS_PROXY environment variables
    ) as client:
        yield client

@pytest.mark.asyncio
async def test_health_endpoint(client):
    """تست سلامت API"""
    response = await client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["app"] == "ERROR-PANEL"

@pytest.mark.asyncio
async def test_token_endpoint(client):
    """تست دریافت توکن"""
    response = await client.get("/api/token")
    assert response.status_code == 200
    assert "token" in response.json()

@pytest.mark.asyncio
async def test_profiles_endpoint(client):
    """تست دریافت پروفایل‌ها (با توکن)"""
    token_response = await client.get("/api/token")
    token = token_response.json()["token"]
    headers = {"X-API-Token": token}
    response = await client.get("/api/profiles/", headers=headers)
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_sources_endpoint(client):
    """تست دریافت منابع (با توکن)"""
    token_response = await client.get("/api/token")
    token = token_response.json()["token"]
    headers = {"X-API-Token": token}
    response = await client.get("/api/sources/", headers=headers)
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_quarantine_endpoint(client):
    """تست دریافت قرنطینه (با توکن)"""
    token_response = await client.get("/api/token")
    token = token_response.json()["token"]
    headers = {"X-API-Token": token}
    response = await client.get("/api/quarantine/", headers=headers)
    assert response.status_code == 200

if __name__ == "__main__":
    pytest.main([__file__, "-v"])