"""
Safe deploy script that:
1. Uploads backend Python files via SFTP
2. Restarts backend/celery containers (no rebuild needed - Python is interpreted)
3. For frontend: uploads source files and runs `npm run build` inside the existing container
   OR uses `docker compose restart frontend` if Next.js supports hot reload
"""
import paramiko
import socket
import time

VPS_IP = '141.136.44.191'
VPS_USER = 'root'
VPS_PASS = '.+H@/Dz5jYxtzs,+'

backend_files = [
    (r'd:\CyberGuard\backend\app\schemas\admin.py',               '/root/cyberguard/backend/app/schemas/admin.py'),
    (r'd:\CyberGuard\backend\app\tasks\m365_scanner.py',          '/root/cyberguard/backend/app/tasks/m365_scanner.py'),
    (r'd:\CyberGuard\backend\app\tasks\m365_token_rotation.py',   '/root/cyberguard/backend/app/tasks/m365_token_rotation.py'),
    (r'd:\CyberGuard\backend\app\services\easm\scanner.py',       '/root/cyberguard/backend/app/services/easm/scanner.py'),
    (r'd:\CyberGuard\backend\app\services\easm\nuclei.py',        '/root/cyberguard/backend/app/services/easm/nuclei.py'),
    (r'd:\CyberGuard\backend\app\services\verification_engine.py','/root/cyberguard/backend/app/services/verification_engine.py'),
    (r'd:\CyberGuard\backend\app\routers\easm.py',                '/root/cyberguard/backend/app/routers/easm.py'),
    (r'd:\CyberGuard\backend\app\routers\m365.py',                '/root/cyberguard/backend/app/routers/m365.py'),
    (r'd:\CyberGuard\backend\app\services\m365_service.py',       '/root/cyberguard/backend/app/services/m365_service.py'),
]

frontend_files = [
    (r'd:\CyberGuard\frontend\lib\api.ts',                                              '/root/cyberguard/frontend/lib/api.ts'),
    (r'd:\CyberGuard\frontend\app\admin\page.tsx',                                      '/root/cyberguard/frontend/app/admin/page.tsx'),
    (r'd:\CyberGuard\frontend\app\dashboard\components\Settings.tsx',                   '/root/cyberguard/frontend/app/dashboard/components/Settings.tsx'),
    (r'd:\CyberGuard\frontend\app\dashboard\components\M365Hub.tsx',                    '/root/cyberguard/frontend/app/dashboard/components/M365Hub.tsx'),
]

def wait_for_ssh(ip, retries=20, delay=8):
    for i in range(1, retries + 1):
        try:
            s = socket.create_connection((ip, 22), timeout=5)
            s.close()
            print(f"SSH port open on attempt {i}!")
            return True
        except Exception as e:
            print(f"Attempt {i}/{retries}: not ready ({e}). Waiting {delay}s...")
            time.sleep(delay)
    return False

print(f"Connecting to VPS {VPS_IP}...")
if not wait_for_ssh(VPS_IP, retries=20, delay=8):
    print("VPS still unreachable after 160s. Please hard reboot from VPS panel.")
    exit(1)

time.sleep(2)
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(VPS_IP, username=VPS_USER, password=VPS_PASS, timeout=15)
print("Connected!")

# ── 1. Ensure all containers are running ────────────────────────────────────
print("\n[1/4] Ensuring all containers are running...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose up -d --no-recreate')
exit_code = stdout.channel.recv_exit_status()
print(f"  docker compose up: exit={exit_code}")

# ── 2. Upload backend Python files via SFTP ─────────────────────────────────
print("\n[2/4] Uploading backend files...")
sftp = c.open_sftp()
for local, remote in backend_files:
    print(f"  SFTP -> {remote}")
    sftp.put(local, remote)

# Upload frontend source files
print("\n[3/4] Uploading frontend source files...")
for local, remote in frontend_files:
    print(f"  SFTP -> {remote}")
    sftp.put(local, remote)
sftp.close()

# ── 3. Restart backend+celery (Python restart picks up new .py files) ────────
print("\n  Restarting backend & celery_worker...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart backend celery_worker')
exit_code = stdout.channel.recv_exit_status()
print(f"  Restart: exit={exit_code}")

# ── 4. Rebuild Next.js INSIDE the existing frontend container ────────────────
# This avoids docker compose build (which would OOM the server)
# Instead we run `npm run build` inside the running container (uses ~1-2GB RAM max)
print("\n[4/4] Building Next.js inside frontend container (safe, no OOM risk)...")
stdin, stdout, stderr = c.exec_command(
    'docker exec cyberguard_frontend sh -c "cd /app && npm run build 2>&1" && '
    'cd /root/cyberguard && docker compose restart frontend'
)
exit_code = stdout.channel.recv_exit_status()
out = stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii')
print(f"  Build output (last 20 lines):\n{''.join(out.splitlines(keepends=True)[-20:])}")
print(f"  Build exit: {exit_code}")

# ── 5. Restart Nginx to pick up new frontend IP ──────────────────────────────
print("\n  Restarting Nginx...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart nginx')
stdout.channel.recv_exit_status()

# ── 6. Verify live site ───────────────────────────────────────────────────────
print("\n  Verifying live site...")
stdin, stdout, stderr = c.exec_command('curl -k -sI https://cyberguardsystem.online/ | head -1')
result = stdout.read().decode('utf-8', errors='ignore').strip()
print(f"  Live site: {result}")

c.close()
print("\nDeployment completed!")
