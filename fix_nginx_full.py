import paramiko
import time

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+', timeout=10)
print("Connected!")

# Find what's using port 80
print("\n[0] What's using port 80/443?")
stdin, stdout, stderr = c.exec_command('ss -tlnp | grep -E ":80|:443" 2>&1')
print(stdout.read().decode('utf-8', errors='ignore').strip())

# Kill anything on port 80 that isn't docker
print("\n[1] Killing any process on port 80...")
stdin, stdout, stderr = c.exec_command('fuser -k 80/tcp 2>&1; fuser -k 443/tcp 2>&1; echo done')
print(stdout.read().decode('utf-8', errors='ignore').strip())
time.sleep(2)

# Full docker compose down then up to reset all networking
print("\n[2] Full docker compose down (removes broken network state)...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose down 2>&1')
exit_code = stdout.channel.recv_exit_status()
print(stdout.read().decode('utf-8', errors='ignore')[-300:])

time.sleep(3)

print("\n[3] docker compose up -d (recreates everything fresh)...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose up -d 2>&1')
exit_code = stdout.channel.recv_exit_status()
out = stdout.read().decode('utf-8', errors='ignore')
print(out[-500:] if len(out) > 500 else out)

time.sleep(15)

# Check status
print("\n[4] Container status...")
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose ps 2>&1')
print(stdout.read().decode('utf-8', errors='ignore'))

# Test site
print("\n[5] Testing site...")
stdin, stdout, stderr = c.exec_command('curl -k -sI https://cyberguardsystem.online/ 2>&1 | head -2')
print(stdout.read().decode('utf-8', errors='ignore').strip())
stdin, stdout, stderr = c.exec_command('curl -k -sI http://cyberguardsystem.online/ 2>&1 | head -2')
print(stdout.read().decode('utf-8', errors='ignore').strip())

c.close()
print("\nDone!")
