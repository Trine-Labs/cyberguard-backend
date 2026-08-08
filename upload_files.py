import paramiko
import time

VPS_IP = '141.136.44.191'
VPS_USER = 'root'
VPS_PASS = '.+H@/Dz5jYxtzs,+'

backend_files = [
    (r'd:\CyberGuard\backend\app\schemas\admin.py',                '/root/cyberguard/backend/app/schemas/admin.py'),
    (r'd:\CyberGuard\backend\app\tasks\m365_scanner.py',           '/root/cyberguard/backend/app/tasks/m365_scanner.py'),
    (r'd:\CyberGuard\backend\app\tasks\m365_token_rotation.py',    '/root/cyberguard/backend/app/tasks/m365_token_rotation.py'),
    (r'd:\CyberGuard\backend\app\services\easm\scanner.py',        '/root/cyberguard/backend/app/services/easm/scanner.py'),
    (r'd:\CyberGuard\backend\app\services\easm\nuclei.py',         '/root/cyberguard/backend/app/services/easm/nuclei.py'),
    (r'd:\CyberGuard\backend\app\services\verification_engine.py', '/root/cyberguard/backend/app/services/verification_engine.py'),
    (r'd:\CyberGuard\backend\app\routers\easm.py',                 '/root/cyberguard/backend/app/routers/easm.py'),
    (r'd:\CyberGuard\backend\app\routers\m365.py',                 '/root/cyberguard/backend/app/routers/m365.py'),
    (r'd:\CyberGuard\backend\app\services\m365_service.py',        '/root/cyberguard/backend/app/services/m365_service.py'),
]

frontend_files = [
    (r'd:\CyberGuard\frontend\lib\api.ts',                                        '/root/cyberguard/frontend/lib/api.ts'),
    (r'd:\CyberGuard\frontend\app\admin\page.tsx',                                '/root/cyberguard/frontend/app/admin/page.tsx'),
    (r'd:\CyberGuard\frontend\app\dashboard\components\Settings.tsx',             '/root/cyberguard/frontend/app/dashboard/components/Settings.tsx'),
    (r'd:\CyberGuard\frontend\app\dashboard\components\M365Hub.tsx',              '/root/cyberguard/frontend/app/dashboard/components/M365Hub.tsx'),
]

print(f"Connecting to {VPS_IP}...")
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(VPS_IP, username=VPS_USER, password=VPS_PASS, timeout=20)
print("Connected!")

# Upload backend files
print("\n[1/3] Uploading backend files...")
sftp = c.open_sftp()
for local, remote in backend_files:
    print(f"  -> {remote.split('/')[-1]}")
    sftp.put(local, remote)

print("\n[2/3] Uploading frontend files...")
for local, remote in frontend_files:
    print(f"  -> {remote.split('/')[-1]}")
    sftp.put(local, remote)
sftp.close()

# Restart backend + celery to pick up new Python files
print("\n[3/3] Restarting backend and celery...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart backend celery_worker celery_beat 2>&1')
exit_code = stdout.channel.recv_exit_status()
print(f"  Done (exit={exit_code})")

time.sleep(5)

# Final verify
print("\nFinal verification...")
stdin, stdout, stderr = c.exec_command('curl -k -sI https://cyberguardsystem.online/ 2>&1 | head -1')
print(f"  Site: {stdout.read().decode('utf-8', errors='ignore').strip()}")

stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose ps --format "{{.Name}} {{.Status}}" 2>&1')
print(stdout.read().decode('utf-8', errors='ignore'))

c.close()
print("\nAll files deployed successfully!")
