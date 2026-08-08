import paramiko
import sys

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

# Query the actual raw Graph API data for managed devices
cmd = '''docker compose exec -T backend python -c "
import asyncio, json
from app.database import AsyncSessionLocal
from sqlalchemy import select
from app.models.m365_credential import M365Credential
from app.services.m365_service import refresh_access_token
from app.services.m365_graph_client import M365GraphClient
from app.services.crypto_service import decrypt_token, EncryptedBlob

async def check():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(M365Credential).where(M365Credential.token_status == 'active'))
        creds = result.scalars().all()
        for cred in creds:
            blob = EncryptedBlob(ciphertext=cred.encrypted_refresh_token, kms_key_id=cred.kms_key_id)
            refresh_token_plaintext = decrypt_token(blob)
            token_data = await refresh_access_token(refresh_token_plaintext)
            access_token = token_data.get('access_token')
            graph = M365GraphClient(cred.tenant_id, access_token, session)
            devices = await graph.get_managed_devices()
            print(f'=== TENANT {cred.tenant_id}: {len(devices)} devices ===')
            for dev in devices:
                print(json.dumps({
                    'deviceName': dev.get('deviceName'),
                    'operatingSystem': dev.get('operatingSystem'),
                    'osVersion': dev.get('osVersion'),
                    'complianceState': dev.get('complianceState'),
                    'windowsDefenderStatus': dev.get('windowsDefenderStatus'),
                    'antiVirusScanState': dev.get('antiVirusScanState'),
                    'managedDeviceOwnerType': dev.get('managedDeviceOwnerType'),
                    'lastSyncDateTime': dev.get('lastSyncDateTime'),
                    'userPrincipalName': dev.get('userPrincipalName'),
                    'deviceRegistrationState': dev.get('deviceRegistrationState'),
                    'managementAgent': dev.get('managementAgent'),
                    'enrolledDateTime': dev.get('enrolledDateTime'),
                    'isEncrypted': dev.get('isEncrypted'),
                    'isSupervised': dev.get('isSupervised'),
                    'jailBroken': dev.get('jailBroken'),
                    'windowsActiveMalwareCount': dev.get('windowsActiveMalwareCount'),
                    'windowsRemediatedMalwareCount': dev.get('windowsRemediatedMalwareCount'),
                    'partnerReportedThreatState': dev.get('partnerReportedThreatState'),
                }, indent=2))
                print('---')
            await graph.close()

asyncio.run(check())
"
'''

stdin, stdout, stderr = c.exec_command(f'cd /root/cyberguard && {cmd}')
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print('STDERR:', err)
c.close()
