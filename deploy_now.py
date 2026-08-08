"""Direct deploy - no waiting, connects immediately, brings everything up."""
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

# Step 1: Bring all containers up
print("\n[1/5] Starting all Docker containers...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose up -d --no-recreate 2>&1')
out = stdout.read().decode('utf-8', errors='ignore')
print(out[-500:] if len(out) > 500 else out)

# Wait for containers to fully start
print("Waiting 10s for containers to initialize...")
time.sleep(10)

# Step 2: Upload backend files via SFTP
print("\n[2/5] Uploading backend files...")
sftp = c.open_sftp()
for local, remote in backend_files:
    print(f"  -> {remote.split('/')[-1]}")
    sftp.put(local, remote)

# Step 3: Upload frontend files
print("\n[3/5] Uploading frontend files...")
for local, remote in frontend_files:
    print(f"  -> {remote.split('/')[-1]}")
    sftp.put(local, remote)
sftp.close()

# Step 4: Restart backend + celery (Python files, no rebuild needed)
print("\n[4/5] Restarting backend and celery...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart backend celery_worker celery_beat 2>&1')
exit_code = stdout.channel.recv_exit_status()
print(f"  Restart: exit={exit_code}")

# Step 5: Build Next.js INSIDE existing container (safe, avoids OOM)
print("\n[5/5] Building Next.js inside existing container (safe build)...")
build_cmd = (
    'docker exec cyberguard_frontend sh -c "cd /app && npm run build 2>&1 | tail -20" && '
    'cd /root/cyberguard && docker compose restart frontend nginx'
)
stdin, stdout, stderr = c.exec_command(build_cmd)
exit_code = stdout.channel.recv_exit_status()
out = stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii')
print(f"  Build output:\n{out[-600:] if len(out) > 600 else out}")
print(f"  Build exit: {exit_code}")

# Final check
print("\nVerifying live site...")
time.sleep(3)
stdin, stdout, stderr = c.exec_command('curl -k -sI https://cyberguardsystem.online/ | head -1')
result = stdout.read().decode('utf-8', errors='ignore').strip()
print(f"  Live site: {result}")

if "200" in result:
    print("\nSite is LIVE!")
elif "301" in result or "302" in result:
    print("\nSite is LIVE (redirect)!")
else:
    print(f"\nUnexpected response: {result}")
    print("Checking Nginx...")
    stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose ps')
    print(stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii'))

c.close()
print("\nDeployment complete.")
