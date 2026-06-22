"""Celery Worker Configuration"""
from celery import Celery
from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "cyberguard_worker",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.m365_token_rotation", "app.tasks.m365_scanner"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
)

# Example beat schedule setup
celery_app.conf.beat_schedule = {
    "rotate-m365-tokens-daily": {
        "task": "app.tasks.m365_token_rotation.rotate_all_tokens",
        "schedule": 86400.0,  # 24 hours
    },
    "scan-m365-tenants-hourly": {
        "task": "app.tasks.m365_scanner.scan_all_tenants",
        "schedule": 3600.0,  # 1 hour
    },
}
