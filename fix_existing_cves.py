import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
import os
from dotenv import load_dotenv

load_dotenv('.env')
db_url = os.environ.get('DATABASE_URL')
if db_url.startswith("postgresql+asyncpg://"):
    pass
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+asyncpg://")

if "?" in db_url:
    db_url = db_url.split("?")[0]

engine = create_async_engine(db_url)

async def run():
    async with AsyncSession(engine) as session:
        # update findings where confidence is 20 and severity is not info
        await session.execute(text("""
            UPDATE findings 
            SET severity = 'info' 
            WHERE evidence->>'confidence' = '20' AND severity != 'info'
        """))
        await session.commit()
        print("Updated potential CVEs to info severity.")

asyncio.run(run())
