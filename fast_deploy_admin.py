import paramiko, time, os, posixpath

VPS_IP = '141.136.44.191'
VPS_USER = 'root'
VPS_PASS = '.+H@/Dz5jYxtzs,+'

LOCAL_BACKEND = r'd:\CyberGuard\backend'
REMOTE_BACKEND = '/root/cyberguard/backend'

LOCAL_FRONTEND = r'd:\CyberGuard\frontend'
REMOTE_FRONTEND = '/root/cyberguard/frontend'

LOCAL_ROOT = r'd:\CyberGuard'
REMOTE_ROOT = '/root/cyberguard'

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

    # Sync config.py and .env
    cfg_local = os.path.join(LOCAL_BACKEND, 'app', 'config.py')
    if os.path.exists(cfg_local):
        sync_pairs.append((cfg_local, posixpath.join(REMOTE_BACKEND, 'app/config.py')))
    env_local = os.path.join(LOCAL_BACKEND, '.env')
    if os.path.exists(env_local):
        sync_pairs.append((env_local, posixpath.join(REMOTE_BACKEND, '.env')))
        sync_pairs.append((env_local, '/root/cyberguard/.env'))

    # Sync docker-compose.yml
    dc_local = os.path.join(LOCAL_ROOT, 'docker-compose.yml')
    if os.path.exists(dc_local):
        sync_pairs.append((dc_local, posixpath.join(REMOTE_ROOT, 'docker-compose.yml')))

    # Sync backup script
    backup_local = os.path.join(LOCAL_BACKEND, 'backup_db.sh')
    if os.path.exists(backup_local):
        sync_pairs.append((backup_local, posixpath.join(REMOTE_ROOT, 'backup_db.sh')))

    # Sync migration script
    migrate_local = os.path.join(LOCAL_BACKEND, 'migrate_neon_to_local.py')
    if os.path.exists(migrate_local):
        sync_pairs.append((migrate_local, posixpath.join(REMOTE_BACKEND, 'migrate_neon_to_local.py')))

    # Sync frontend app, components, lib, hooks, public
    for folder in ['app', 'components', 'lib', 'hooks', 'public']:
        target_dir = os.path.join(LOCAL_FRONTEND, folder)
        if not os.path.exists(target_dir):
            continue
        for root, dirs, files in os.walk(target_dir):
            for f in files:
                if f.endswith(('.ts', '.tsx', '.json', '.css', '.svg', '.png', '.ico')):
                    local_path = os.path.join(root, f)
                    rel_path = os.path.relpath(local_path, LOCAL_FRONTEND).replace('\\', '/')
                    remote_path = posixpath.join(REMOTE_FRONTEND, rel_path)
                    sync_pairs.append((local_path, remote_path))

    return sync_pairs

print("Connecting to VPS...")
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(VPS_IP, username=VPS_USER, password=VPS_PASS, timeout=30)
print("Connected!")

sync_pairs = get_files_to_sync()
print(f"Preparing {len(sync_pairs)} remote directories...")
unique_dirs = set(posixpath.dirname(remote) for _, remote in sync_pairs)
dir_cmd = "mkdir -p " + " ".join(f'"{d}"' for d in unique_dirs)
stdin, stdout, stderr = c.exec_command(dir_cmd)
stdout.channel.recv_exit_status()

print(f"Uploading {len(sync_pairs)} source files to VPS...")
sftp = c.open_sftp()
for idx, (local, remote) in enumerate(sync_pairs, 1):
    try:
        sftp.put(local, remote)
    except Exception as ex:
        print(f"  Retry on {remote}: {ex}")
        time.sleep(1)
        sftp.put(local, remote)

sftp.close()
print("All source files uploaded successfully!")

# Ensure postgres container is running first (do NOT force-recreate — preserves data volume)
print("\n[0/3] Ensuring PostgreSQL container is up (no force-recreate)...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose up -d postgres 2>&1')
exit_code = stdout.channel.recv_exit_status()
out = stdout.read().decode('utf-8', errors='ignore')
print(f"  Postgres up exit: {exit_code}\n{out}")

# Wait for postgres health check
print("  Waiting for PostgreSQL health check...")
time.sleep(8)
stdin, stdout, stderr = c.exec_command('docker inspect --format="{{.State.Health.Status}}" cyberguard_postgres 2>&1')
health = stdout.read().decode('utf-8', errors='ignore').strip()
print(f"  PostgreSQL health: {health}")

# Copy backend files into running container & rebuild images
print("\n[1/3] Rebuilding backend container image on VPS...")
c.exec_command('docker cp /root/cyberguard/backend/app/. cyberguard_backend:/app/app/')
c.exec_command('docker cp /root/cyberguard/backend/app/. cyberguard_celery:/app/app/')

stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose build backend celery_worker celery_beat 2>&1')
print(f"  Backend build exit: {stdout.channel.recv_exit_status()}")

# Rebuild frontend image
print("\n[2/3] Rebuilding frontend container image on VPS...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose build frontend 2>&1')
exit_code = stdout.channel.recv_exit_status()
out = stdout.read().decode('utf-8', errors='ignore')
print(f"  Frontend build exit: {exit_code}\n  Output tail:\n{out[-400:] if len(out) > 400 else out}")

# Recreate app containers (NOT postgres — preserves data)
print("\n[3/3] Starting & recreating app containers on VPS...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose up -d --force-recreate backend celery_worker celery_beat frontend 2>&1')
exit_code = stdout.channel.recv_exit_status()
out = stdout.read().decode('utf-8', errors='ignore')
print(f"  Compose Up exit: {exit_code}\n{out}")

time.sleep(5)
print("Reloading nginx upstream routes...")
stdin, stdout, stderr = c.exec_command('docker restart cyberguard_nginx')
stdout.channel.recv_exit_status()

# Verify route
stdin, stdout, stderr = c.exec_command('curl -k -sI https://cyberguardsystem.online/auth/login 2>&1 | head -5')
print(f"\nAuth Login Route Status:\n{stdout.read().decode('utf-8', errors='ignore').strip()}")

stdin, stdout, stderr = c.exec_command('docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"')
print(f"\nLive Containers:\n{stdout.read().decode('utf-8', errors='ignore').strip()}")

c.close()
print("\nDeployment complete!")

