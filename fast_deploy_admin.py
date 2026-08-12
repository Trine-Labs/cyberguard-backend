import paramiko, time, os, posixpath

VPS_IP = '141.136.44.191'
VPS_USER = 'root'
VPS_PASS = '.+H@/Dz5jYxtzs,+'

LOCAL_BACKEND = r'd:\CyberGuard\backend'
REMOTE_BACKEND = '/root/cyberguard/backend'

LOCAL_FRONTEND = r'd:\CyberGuard\frontend'
REMOTE_FRONTEND = '/root/cyberguard/frontend'

def get_files_to_sync():
    sync_pairs = []
    
    # Sync backend app & config
    for root, dirs, files in os.walk(os.path.join(LOCAL_BACKEND, 'app')):
        for f in files:
            if f.endswith('.py'):
                local_path = os.path.join(root, f)
                rel_path = os.path.relpath(local_path, LOCAL_BACKEND).replace('\\', '/')
                remote_path = posixpath.join(REMOTE_BACKEND, rel_path)
                sync_pairs.append((local_path, remote_path))

    # Sync config.py
    cfg_local = os.path.join(LOCAL_BACKEND, 'app', 'config.py')
    if os.path.exists(cfg_local):
        sync_pairs.append((cfg_local, posixpath.join(REMOTE_BACKEND, 'app/config.py')))

    # Sync frontend app, components, lib
    for folder in ['app', 'components', 'lib']:
        target_dir = os.path.join(LOCAL_FRONTEND, folder)
        if not os.path.exists(target_dir):
            continue
        for root, dirs, files in os.walk(target_dir):
            for f in files:
                if f.endswith(('.ts', '.tsx', '.json', '.css')):
                    local_path = os.path.join(root, f)
                    rel_path = os.path.relpath(local_path, LOCAL_FRONTEND).replace('\\', '/')
                    remote_path = posixpath.join(REMOTE_FRONTEND, rel_path)
                    sync_pairs.append((local_path, remote_path))

    return sync_pairs

print("Connecting to VPS...")
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(VPS_IP, username=VPS_USER, password=VPS_PASS, timeout=15)
print("Connected!")

sftp = c.open_sftp()
sync_pairs = get_files_to_sync()

print(f"\nUploading {len(sync_pairs)} source files to VPS...")
for local, remote in sync_pairs:
    remote_dir = posixpath.dirname(remote)
    c.exec_command(f"mkdir -p {remote_dir}")
    sftp.put(local, remote)

sftp.close()

# Copy backend files into running container & restart backend
print("\n[1/2] Updating backend container...")
c.exec_command('docker cp /root/cyberguard/backend/app/. cyberguard_backend:/app/app/')
c.exec_command('docker cp /root/cyberguard/backend/app/. cyberguard_celery:/app/app/')
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart backend celery 2>&1')
print(f"  Backend restart exit: {stdout.channel.recv_exit_status()}")

# Rebuild frontend image
print("\n[2/2] Rebuilding frontend container image on VPS...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose build frontend 2>&1')
exit_code = stdout.channel.recv_exit_status()
out = stdout.read().decode('utf-8', errors='ignore')
print(f"  Build exit: {exit_code}\n  Output tail:\n{out[-500:] if len(out) > 500 else out}")

print("\nStarting frontend container...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose up -d frontend 2>&1')
print(f"  Up exit: {stdout.channel.recv_exit_status()}")

time.sleep(4)

# Verify route
stdin, stdout, stderr = c.exec_command('curl -k -sI https://cyberguardsystem.online/auth/login 2>&1 | head -3')
print(f"\nAuth Login Route Status:\n{stdout.read().decode('utf-8', errors='ignore').strip()}")

c.close()
print("\nDeployment complete!")
