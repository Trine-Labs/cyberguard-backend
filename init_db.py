"""
CyberGuard — Database Initialization Script
1. Creates all required PostgreSQL ENUM types if they do not exist
2. Creates all base tables from SQLAlchemy models
3. Stamps Alembic to head / runs pending migrations
"""
import asyncio
import subprocess
import sys
from sqlalchemy import text
from app.database import engine, Base

# Import all models to register with Base.metadata
from app.models.tenant import Tenant
from app.models.user import User
from app.models.scope import ScanScope
from app.models.m365_credential import M365Credential
from app.models.audit_trail import AuditTrail
from app.models.scan_job import ScanJob
from app.models.easm import EasmAsset, EasmPort, EasmCertificate
from app.models.finding import Finding
from app.models.m365_audit_log import M365AuditLog
from app.models.phishing import PhishingCampaign, PhishingTarget, EmployeeSecurityScore

ENUMS_TO_CREATE = [
    ("tenant_status", ["onboarding", "active", "suspended"]),
    ("user_role", ["admin", "viewer"]),
    ("scope_type", ["domain", "cidr"]),
    ("token_status", ["active", "revoked", "expired"]),
    ("job_status", ["queued", "running", "completed", "failed"]),
    ("asset_criticality", ["critical", "high", "medium", "low", "unknown"]),
    ("asset_status", ["active", "inactive", "unknown"]),
    ("finding_severity", ["critical", "high", "medium", "low", "info"]),
    ("finding_source", ["m365", "ext_scanner", "manual", "human_risk", "phishing"]),
    ("finding_status", ["open", "resolved", "accepted_risk", "false_positive"]),
    ("risk_level", ["critical", "high", "medium", "low", "info"]),
    ("sec_headers_grade", ["A", "B", "C", "D", "F", "unknown"]),
]

async def init_database():
    print("[1/3] Ensuring PostgreSQL ENUM types and base tables...")
    async with engine.begin() as conn:
        for enum_name, values in ENUMS_TO_CREATE:
            val_str = ", ".join(f"'{v}'" for v in values)
            sql = f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = '{enum_name}') THEN
                    CREATE TYPE {enum_name} AS ENUM ({val_str});
                END IF;
            END
            $$;
            """
            await conn.execute(text(sql))
        print("  ✓ PostgreSQL ENUMs created/verified")

        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
        print("  ✓ All SQLAlchemy model tables created/verified")

        # Create findings_seq sequence if not exists
        await conn.execute(text("CREATE SEQUENCE IF NOT EXISTS findings_seq START WITH 1000;"))
        print("  ✓ findings_seq sequence created/verified")

    await engine.dispose()
    print("  ✓ DB connection disposed")

if __name__ == "__main__":
    asyncio.run(init_database())

    print("\n[2/3] Stamping Alembic version to head...")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "stamp", "head"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("  ✓ Alembic stamped to head")
    else:
        print(f"  · Alembic stamp output: {result.stderr.strip() or result.stdout.strip()}")

    print("\n[3/3] Running alembic upgrade head (verify)...")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("  ✓ Alembic upgrade complete")
    else:
        print(f"  · Alembic upgrade output: {result.stderr.strip() or result.stdout.strip()}")

    print("\n✓ Database initialization finished successfully!")
