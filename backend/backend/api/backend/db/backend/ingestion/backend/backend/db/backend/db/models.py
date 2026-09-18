"""
SQLAlchemy models for Log Sentinel.

Three tables:
- LogEvent  : every parsed log line + its anomaly score
- Anomaly   : flagged events (score above threshold) — subset of LogEvent
- Feedback  : user-confirmed labels (true positive / false positive) for retraining
"""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Boolean, Text, Index
)
from db.session import Base


class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Parsed fields
    ip = Column(String(64), index=True)
    method = Column(String(16))
    path = Column(String(512))
    status = Column(Integer, index=True)
    bytes_sent = Column(Integer, default=0)
    response_time_ms = Column(Float, default=0.0)
    user_agent = Column(String(512), nullable=True)

    # ML scoring
    anomaly_score = Column(Float, default=0.0, index=True)
    is_anomaly = Column(Boolean, default=False, index=True)

    # Raw line kept for auditing / debugging
    raw = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_events_anomaly_time", "is_anomaly", "timestamp"),
    )


class Feedback(Base):
    """User-provided labels — the 'semi' in semi-supervised."""
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, index=True)
    is_true_anomaly = Column(Boolean)
    note = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
