import asyncio
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from app.services.crypto_service import decrypt_token, EncryptedBlob
from app.services.m365_service import refresh_access_token

async def main():
    engine = create_async_engine('postgresql+asyncpg://neondb_owner:npg_taqe1AmB5OGL@ep-wispy-sea-aotmlgko-pooler.c-2.ap-southeast-1.aws.neon.tech/neondb?ssl=require')
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        result = await session.execute(text("SELECT encrypted_refresh_token, kms_key_id FROM m365_credentials LIMIT 1"))
        row = result.fetchone()
        
    blob = EncryptedBlob(ciphertext=row[0], kms_key_id=row[1])
    refresh_token = decrypt_token(blob)
    
    tokens = await refresh_access_token(refresh_token)
    access_token = tokens["access_token"]
    
    async with httpx.AsyncClient() as client:
        r = await client.get('https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails', headers={'Authorization': f'Bearer {access_token}'})
        print(r.status_code)
        print(r.text)

if __name__ == '__main__':
    asyncio.run(main())
