import asyncio
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

async def main():
    engine = create_async_engine('postgresql+asyncpg://neondb_owner:npg_taqe1AmB5OGL@ep-wispy-sea-aotmlgko-pooler.c-2.ap-southeast-1.aws.neon.tech/neondb?ssl=require')
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        result = await session.execute(text('SELECT access_token FROM m365_credentials LIMIT 1'))
        row = result.fetchone()
        token = row[0] if row else None
        
    print('Got token' if token else 'No token')
    if token:
        async with httpx.AsyncClient() as client:
            r = await client.get('https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails', headers={'Authorization': f'Bearer {token}'})
            print('old:', r.status_code, r.text[:500])
            r2 = await client.get('https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails', headers={'Authorization': f'Bearer {token}'})
            print('new:', r2.status_code, r2.text[:500])

if __name__ == '__main__':
    asyncio.run(main())
