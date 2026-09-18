"""
Log Sentinel — FastAPI entry point.

Run locally:
    uvicorn main:app --reload

Endpoints:
    GET  /              — service info
    GET  /health        — health check
    GET  /docs          — interactive API docs (Swagger)
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from db.session import init_db
from api import health

# --- App setup ---
app = FastAPI(
    title="Log Sentinel",
    description="Real-time anomaly detection for web server logs (semi-supervised).",
    version="0.1.0",
)

# --- CORS ---
# ALLOWED_ORIGINS is a comma-separated list set as an env var on Render.
# In dev, defaults to "*" so localhost works.
_raw = os.getenv("ALLOWED_ORIGINS", "*")
allowed_origins = ["*"] if _raw.strip() == "*" else [o.strip() for o in _raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Startup ---
@app.on_event("startup")
def _startup():
    init_db()


# --- Routes ---
app.include_router(health.router)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
