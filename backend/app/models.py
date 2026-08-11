"""ERROR-PANEL — SQLAlchemy ORM models.

Tables: sources, profiles, metrics, security_scans, audit_logs, settings
Relationships: source.profiles, profile.metrics, profile.security_scans
"""

from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from .db import Base


class Source(Base):
    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text, nullable=False)
    type = Column(Text, nullable=False)  # github | url | manual
    url = Column(Text, nullable=True)
    status = Column(Text, nullable=False, default="pending_review")
    # pending_review | active | paused | suspicious | blocked
    reputation_score = Column(Integer, nullable=False, default=50)
    last_sync_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    # Relationships
    profiles = relationship("Profile", back_populates="source", lazy="selectin")


class Profile(Base):
    __tablename__ = "profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_id = Column(Integer, ForeignKey("sources.id"), nullable=True)
    name = Column(Text, nullable=False)
    protocol = Column(Text, nullable=False)
    # wireguard | openvpn | vless | vmess | xray | shadowsocks | trojan
    server_host = Column(Text, nullable=True)
    server_port = Column(Integer, nullable=True)
    country_code = Column(Text, nullable=True)  # ISO 3166-1 alpha-2
    status = Column(Text, nullable=False, default="new")
    # new | quarantined | pending_review | approved | tested | failed | blocked | archived
    risk_score = Column(Integer, nullable=False, default=0)
    duplicate_of = Column(Integer, ForeignKey("profiles.id"), nullable=True)
    fingerprint = Column(String(64), nullable=True, index=True)  # SHA-256 hex for dedup
    config_ref = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    # Relationships
    source = relationship("Source", back_populates="profiles")
    metrics = relationship("Metric", back_populates="profile", lazy="selectin")
    security_scans = relationship("SecurityScan", back_populates="profile", lazy="selectin")


class Metric(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(Integer, ForeignKey("profiles.id"), nullable=False)
    checked_at = Column(DateTime, nullable=False, default=func.now())
    ping_ms = Column(Float, nullable=True)
    packet_loss_pct = Column(Float, nullable=True)
    jitter_ms = Column(Float, nullable=True)
    download_mbps = Column(Float, nullable=True)
    upload_mbps = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    profile = relationship("Profile", back_populates="metrics")


class SecurityScan(Base):
    __tablename__ = "security_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(Integer, ForeignKey("profiles.id"), nullable=False)
    scanned_at = Column(DateTime, nullable=False, default=func.now())
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(Text, nullable=False, default="low")
    # low | medium | high | critical
    warnings_json = Column(Text, nullable=True)  # JSON array
    recommendation = Column(Text, nullable=False, default="review")
    # approve | review | block

    # Relationships
    profile = relationship("Profile", back_populates="security_scans")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    action = Column(Text, nullable=False)
    entity_type = Column(Text, nullable=False)
    entity_id = Column(Integer, nullable=False)
    details_json = Column(Text, nullable=True)  # JSON object


class Settings(Base):
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)  # JSON text

