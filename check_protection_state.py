import paramiko
import sys

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

cmd = '''docker compose exec -T backend python -c "
import asyncio, json
from app.database import AsyncSessionLocal
from sqlalchemy import select
from app.models.m365_credential import M365Credential
from app.services.m365_service import refresh_access_token
from app.services.crypto_service import decrypt_token, EncryptedBlob
import httpx

async def check():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(M365Credential).where(M365Credential.token_status == 'active').limit(1))
        cred = result.scalar_one_or_none()
        if not cred:
            print('No active creds')
            return
        blob = EncryptedBlob(ciphertext=cred.encrypted_refresh_token, kms_key_id=cred.kms_key_id)
        refresh_token_plaintext = decrypt_token(blob)
        token_data = await refresh_access_token(refresh_token_plaintext)
        access_token = token_data.get('access_token')
        
        headers = {'Authorization': f'Bearer {access_token}'}
        async with httpx.AsyncClient() as client:
            # First get the device IDs
            r1 = await client.get('https://graph.microsoft.com/beta/deviceManagement/managedDevices', headers=headers)
            devices = r1.json().get('value', [])
            for dev in devices:
                device_id = dev.get('id')
                device_name = dev.get('deviceName')
                os = dev.get('operatingSystem', '')
                if 'Windows' not in os:
                    continue
                print(f'=== Device: {device_name} (id={device_id}) ===')
                
                # Query windowsProtectionState for this device
                r2 = await client.get(f'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{device_id}/windowsProtectionState', headers=headers)
                print(f'Status: {r2.status_code}')
                if r2.status_code == 200:
                    data = r2.json()
                    print(json.dumps(data, indent=2, default=str))
                else:
                    print(r2.text[:500])
                print('---')

asyncio.run(check())
"
'''

stdin, stdout, stderr = c.exec_command(f'cd /root/cyberguard && {cmd}')
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print('STDERR:', err[-300:])
c.close()
