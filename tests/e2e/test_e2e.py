import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
"""
تست End-to-End با سرور واقعی
برای اجرا: ابتدا سرور را اجرا کنید، سپس این تست را اجرا کنید.
"""

import pytest
import httpx

BASE_URL = "http://127.0.0.1:8000"

@pytest.mark.asyncio
async def test_health_endpoint():
    """تست سلامت API"""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"

@pytest.mark.asyncio
async def test_token_endpoint():
    """تست دریافت توکن"""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/api/token")
        assert response.status_code == 200
        assert "token" in response.json()

@pytest.mark.asyncio
async def test_profiles_endpoint():
    """تست دریافت پروفایل‌ها (با توکن)"""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        token_response = await client.get("/api/token")
        token = token_response.json()["token"]
        headers = {"X-API-Token": token}
        response = await client.get("/api/profiles/", headers=headers)
        assert response.status_code == 200

@pytest.mark.asyncio
async def test_sources_endpoint():
    """تست دریافت منابع (با توکن)"""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        token_response = await client.get("/api/token")
        token = token_response.json()["token"]
        headers = {"X-API-Token": token}
        response = await client.get("/api/sources/", headers=headers)
        assert response.status_code == 200

@pytest.mark.asyncio
async def test_quarantine_endpoint():
    """تست دریافت قرنطینه (با توکن)"""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        token_response = await client.get("/api/token")
        token = token_response.json()["token"]
        headers = {"X-API-Token": token}
        response = await client.get("/api/quarantine/", headers=headers)
        assert response.status_code == 200

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

