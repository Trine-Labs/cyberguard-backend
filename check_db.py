import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
import json

async def main():
    engine = create_async_engine('postgresql+asyncpg://neondb_owner:npg_taqe1AmB5OGL@ep-wispy-sea-aotmlgko-pooler.c-2.ap-southeast-1.aws.neon.tech/neondb?ssl=require')
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        result = await session.execute(text("SELECT hub_state FROM m365_credentials LIMIT 1"))
        row = result.fetchone()
        if row and row[0]:
            state = row[0]
            if isinstance(state, str):
                state = json.loads(state)
            print("Timestamp:", state.get("timestamp"))
            mfa = state.get("mfa_details", [])
            print("MFA Details Count:", len(mfa))
            print("MFA Sample:", mfa[:1] if mfa else "None")
        else:
            print("No hub state")

if __name__ == '__main__':
    asyncio.run(main())
