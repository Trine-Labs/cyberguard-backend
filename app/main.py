"""
CyberGuard Backend — FastAPI Application Entrypoint
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.config import get_settings
from app.routers.auth import router as auth_router
from app.routers.onboarding import router as onboarding_router
from app.routers.m365 import router as m365_router
from app.routers.dashboard import router as dashboard_router
from app.routers.easm import router as easm_router
from app.routers.findings import router as findings_router
from app.routers.settings import router as settings_router

from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from fastapi_cache.backends.inmemory import InMemoryBackend
import redis.asyncio as redis

settings = get_settings()
logger = logging.getLogger(__name__)

# Silence noisy SQLAlchemy logs (no longer needed since echo=False)
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)


async def _warmup_pool():
    """
    Pre-warm the SQLAlchemy connection pool on startup.
    Opens and immediately returns 3 connections so the pool is populated
    before the first real request arrives — eliminates cold-start delay.
    """
    from app.database import engine
    from sqlalchemy import text
    try:
        # Properly use context managers to check in/out of the pool
        async def ping_db():
            async with engine.connect() as conn:
                # Query custom types to force asyncpg to cache their OIDs globally on the connection
                await conn.execute(text("SELECT 'open'::finding_status, 'critical'::finding_severity, 'active'::asset_status"))

        
        # Fire 10 concurrent connections to warm up the pool
        # Wrapping in wait_for to prevent infinite hangs if Neon rate limits the connection storm
        await asyncio.wait_for(
            asyncio.gather(*[ping_db() for _ in range(10)]), 
            timeout=15.0
        )
        
        logger.info("[CyberGuard] Connection pool warmed up (10 connections)")
    except Exception as e:
        logger.warning(f"[CyberGuard] Pool warmup failed (non-fatal): {e}")


async def _keep_db_alive():
    """
    Background task to ping the database every 4 minutes.
    This prevents Neon DB serverless compute from scaling to zero (which causes
    5-10s cold starts) and keeps the asyncpg connections from being dropped by
    stateful firewalls or Neon's proxy.
    """
    from app.database import engine
    from sqlalchemy import text
    while True:
        try:
            await asyncio.sleep(240)  # 4 minutes
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            logger.debug("[CyberGuard] Database keep-alive ping sent")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"[CyberGuard] DB keep-alive ping failed: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle handler."""
    logger.info(f"[CyberGuard] API starting up [{settings.app_env}]")
    
    # Initialize Redis Cache with fallback
    try:
        redis_client = redis.from_url(settings.redis_url, encoding="utf8", decode_responses=False, socket_timeout=1)
        # Test connection
        await redis_client.ping()
        FastAPICache.init(RedisBackend(redis_client), prefix="cg-cache")
        logger.info(f"[CyberGuard] Redis cache initialized at {settings.redis_url}")
    except Exception as e:
        logger.warning(f"[CyberGuard] Redis unavailable ({e}). Falling back to InMemoryBackend.")
        FastAPICache.init(InMemoryBackend(), prefix="cg-cache")

    # Warm up connection pool blocking startup so first request isn't slow
    await _warmup_pool()
    
    # Start background keep-alive to prevent Neon cold starts
    keep_alive_task = asyncio.create_task(_keep_db_alive())
    
    yield
    
    keep_alive_task.cancel()
    logger.info("[CyberGuard] API shutting down")
    # Dispose engine to cleanly close all pooled connections
    from app.database import engine
    await engine.dispose()


import time
from fastapi import Request

app = FastAPI(
    title="CyberGuard API",
    description="Multi-tenant Cybersecurity SaaS — External Attack Surface Management + M365 Identity Security",
    version="1.0.0",
    docs_url="/api/docs",   # Always available in dev
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    print(f"[Timing] {request.method} {request.url.path} took {process_time:.4f} secs")
    return response

# GZip compression — reduces JSON response size by ~70% for large payloads
app.add_middleware(GZipMiddleware, minimum_size=500)

# CORS — restrict to frontend origin in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# Mount routers
app.include_router(auth_router)
app.include_router(onboarding_router)
app.include_router(m365_router)
app.include_router(dashboard_router)
app.include_router(easm_router)
app.include_router(findings_router)
app.include_router(settings_router)


@app.get("/api/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "CyberGuard API",
        "version": "1.0.0",
        "environment": settings.app_env,
    }
