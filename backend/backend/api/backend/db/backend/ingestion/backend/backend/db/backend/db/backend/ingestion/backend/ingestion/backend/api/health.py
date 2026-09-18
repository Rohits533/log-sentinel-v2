"""Health and metadata endpoints."""
from fastapi import APIRouter
from datetime import datetime

router = APIRouter(tags=["health"])


@router.get("/")
def root():
    return {
        "service": "log-sentinel",
        "version": "0.1.0",
        "description": "Real-time anomaly detection for web server logs",
        "docs": "/docs",
    }


@router.get("/health")
def health():
    return {
        "status": "ok",
        "time": datetime.utcnow().isoformat(),
    }
