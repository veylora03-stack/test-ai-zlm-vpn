"""
Shared test fixtures for ERROR-PANEL.
"""
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock

@pytest.fixture
def mock_profile():
    """Mock Profile object for scanner tests."""
    profile = MagicMock()
    profile.id = 1
    profile.protocol = "openvpn"
    profile.server_host = "vpn.example.com"
    profile.server_port = 443
    profile.config_ref = "test_config.ovpn"
    profile.source_id = None
    return profile

@pytest.fixture
def mock_raw_text():
    """Sample OpenVPN config text for tests."""
    return """
client
dev tun
proto udp
remote vpn.example.com 443
cipher AES-256-CBC
auth SHA256
<ca>
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</ca>
<cert>
...
</cert>
<key>
...
</key>
remote-cert-tls server
auth-user-pass
"""

@pytest.fixture
def mock_db_session():
    """Mock AsyncSession for testing async DB functions without a real database."""
    session = AsyncMock()
    # Mock the execute chain: session.execute().scalars().all() / .scalar_one_or_none()
    session.execute.return_value.scalars.return_value.all.return_value = []
    session.execute.return_value.scalar_one_or_none.return_value = None
    session.execute.return_value.scalar.return_value = 0
    return session
