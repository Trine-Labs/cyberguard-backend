import paramiko, time

VPS_IP = '141.136.44.191'
VPS_USER = 'root'
VPS_PASS = '.+H@/Dz5jYxtzs,+'

backend_files = [
    (r'd:\CyberGuard\backend\app\routers\admin.py', '/root/cyberguard/backend/app/routers/admin.py'),
    (r'd:\CyberGuard\backend\app\routers\dashboard.py', '/root/cyberguard/backend/app/routers/dashboard.py'),
]

frontend_files = [
    (r'd:\CyberGuard\frontend\lib\api.ts',                             '/root/cyberguard/frontend/lib/api.ts'),
    (r'd:\CyberGuard\frontend\app\dashboard\components\ScanLogs.tsx',  '/root/cyberguard/frontend/app/dashboard/components/ScanLogs.tsx'),
    (r'd:\CyberGuard\frontend\app\dashboard\components\M365Hub.tsx',   '/root/cyberguard/frontend/app/dashboard/components/M365Hub.tsx'),
    (r'd:\CyberGuard\frontend\app\admin\layout.tsx',                  '/root/cyberguard/frontend/app/admin/layout.tsx'),
    (r'd:\CyberGuard\frontend\app\admin\page.tsx',                    '/root/cyberguard/frontend/app/admin/page.tsx'),
    (r'd:\CyberGuard\frontend\app\admin\components\AdminScanLogs.tsx', '/root/cyberguard/frontend/app/admin/components/AdminScanLogs.tsx'),
    (r'd:\CyberGuard\frontend\app\admin\scan-logs\page.tsx',          '/root/cyberguard/frontend/app/admin/scan-logs/page.tsx'),
]

print("Connecting to VPS...")
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(VPS_IP, username=VPS_USER, password=VPS_PASS, timeout=15)
print("Connected!")

sftp = c.open_sftp()

for d in ['/root/cyberguard/frontend/app/admin/components', '/root/cyberguard/frontend/app/admin/scan-logs']:
    try:
        sftp.mkdir(d)
    except Exception:
        pass

print("\nUploading source files...")
for local, remote in backend_files + frontend_files:
    print(f"  -> {remote.split('/')[-1]}")
    sftp.put(local, remote)

sftp.close()

# Copy backend files into running container & restart backend
print("\n[1/2] Updating backend container...")
c.exec_command('docker cp /root/cyberguard/backend/app/. cyberguard_backend:/app/app/')
c.exec_command('docker cp /root/cyberguard/backend/app/. cyberguard_celery:/app/app/')
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart backend 2>&1')
print(f"  Backend restart exit: {stdout.channel.recv_exit_status()}")

# Rebuild frontend image with new admin scan logs and sidebar
print("\n[2/2] Rebuilding frontend container image on VPS...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose build frontend 2>&1')
exit_code = stdout.channel.recv_exit_status()
out = stdout.read().decode('utf-8', errors='ignore')
print(f"  Build exit: {exit_code}\n  Output tail:\n{out[-500:] if len(out) > 500 else out}")

print("\nStarting frontend container...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose up -d frontend 2>&1')
print(f"  Up exit: {stdout.channel.recv_exit_status()}")

time.sleep(4)

# Verify routes
stdin, stdout, stderr = c.exec_command('curl -k -sI https://cyberguardsystem.online/admin/scan-logs 2>&1 | head -3')
print(f"\nAdmin Scan Logs Route Status:\n{stdout.read().decode('utf-8', errors='ignore').strip()}")

c.close()
print("\nDeployment complete!")
