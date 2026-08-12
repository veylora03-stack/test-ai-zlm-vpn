"""ERROR-PANEL — Pydantic v2 request/response schemas.

Uses from_attributes=True for ORM model conversion.
"""

from datetime import datetime
from typing import Optional, Literal

from typing import Literal
from pydantic import BaseModel, Field, ConfigDict


# ── Sources ──────────────────────────────────────────────────────────────────

class SourceCreate(BaseModel):
    name: str
    type: Literal['github', 'url', 'manual']
    url: Optional[str] = None
    status: Literal['pending_review', 'active', 'paused', 'suspicious', 'blocked'] = 'pending_review'
    reputation_score: int = 50
    notes: Optional[str] = None


class SourceUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    url: Optional[str] = None
    status: Optional[str] = None
    reputation_score: Optional[int] = None
    notes: Optional[str] = None


class SourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: str
    url: Optional[str] = None
    status: str
    reputation_score: int
    last_sync_at: Optional[datetime] = None
    last_error: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# ── Profiles ─────────────────────────────────────────────────────────────────

class ProfileCreate(BaseModel):
    source_id: Optional[int] = None
    name: str
    protocol: str
    # wireguard | openvpn | vless | vmess | xray | shadowsocks | trojan
    server_host: Optional[str] = Field(None, max_length=255, description="Server hostname or IP")
    server_port: Optional[int] = Field(None, ge=1, le=65535, description="Port must be 1-65535")
    country_code: Optional[str] = None
    status: Literal['new', 'quarantined', 'pending_review', 'approved', 'tested', 'failed', 'blocked', 'archived'] = 'new'
    risk_score: int = 0
    duplicate_of: Optional[int] = None
    config_ref: Optional[str] = None
    notes: Optional[str] = None


class ProfileUpdate(BaseModel):
    source_id: Optional[int] = None
    name: Optional[str] = None
    protocol: Optional[str] = None
    server_host: Optional[str] = Field(None, max_length=255, description="Server hostname or IP")
    server_port: Optional[int] = Field(None, ge=1, le=65535, description="Port must be 1-65535")
    country_code: Optional[str] = None
    status: Optional[str] = None
    risk_score: Optional[int] = None
    duplicate_of: Optional[int] = None
    config_ref: Optional[str] = None
    notes: Optional[str] = None


class ProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_id: Optional[int] = None
    name: str
    protocol: str
    server_host: Optional[str] = Field(None, max_length=255, description="Server hostname or IP")
    server_port: Optional[int] = Field(None, ge=1, le=65535, description="Port must be 1-65535")
    country_code: Optional[str] = None
    status: str
    risk_score: int
    duplicate_of: Optional[int] = None
    fingerprint: Optional[str] = None
    config_ref: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# ── Metrics ──────────────────────────────────────────────────────────────────

class MetricResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    profile_id: int
    checked_at: datetime
    ping_ms: Optional[float] = None
    packet_loss_pct: Optional[float] = None
    jitter_ms: Optional[float] = None
    download_mbps: Optional[float] = None
    upload_mbps: Optional[float] = None
    error_message: Optional[str] = None


# ── Security Scans ───────────────────────────────────────────────────────────

class SecurityScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    profile_id: int
    scanned_at: datetime
    risk_score: int
    risk_level: str
    warnings_json: Optional[str] = None
    recommendation: str


# ── Manual Metric Submission ─────────────────────────────────────────────────

class ManualMetricCreate(BaseModel):
    profile_id: int
    download_mbps: float = Field(ge=0, description="Download speed in Mbps (must be >= 0)")
    upload_mbps: float = Field(ge=0, description="Upload speed in Mbps (must be >= 0)")
    ping_ms: Optional[float] = Field(None, ge=0, description="Ping in ms (must be >= 0)")


# ── Audit Logs ───────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    action: str
    entity_type: str
    entity_id: int
    details_json: Optional[str] = None

