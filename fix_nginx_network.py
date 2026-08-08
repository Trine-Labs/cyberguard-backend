import paramiko
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+', timeout=10)

print("=== Fixing Nginx network issue ===")

# Connect nginx to the cyberguard_default network
print("\n[1] Connecting nginx to cyberguard_default network...")
stdin, stdout, stderr = c.exec_command('docker network connect cyberguard_default cyberguard_nginx 2>&1')
out = stdout.read().decode('utf-8', errors='ignore').strip()
err = stderr.read().decode('utf-8', errors='ignore').strip()
print(f"  out: {out or '(none)'}")
print(f"  err: {err or '(none)'}")

# Now restart nginx
print("\n[2] Restarting nginx...")
stdin, stdout, stderr = c.exec_command('docker restart cyberguard_nginx 2>&1')
exit_code = stdout.channel.recv_exit_status()
out = stdout.read().decode('utf-8', errors='ignore').strip()
print(f"  result: {out}, exit={exit_code}")

import time
time.sleep(5)

# Verify nginx is up
print("\n[3] Checking nginx status...")
stdin, stdout, stderr = c.exec_command('docker inspect cyberguard_nginx --format "Status={{.State.Status}} Running={{.State.Running}}" 2>&1')
print(f"  {stdout.read().decode('utf-8', errors='ignore').strip()}")

# Check nginx logs
print("\n[4] Nginx logs (last 10 lines)...")
stdin, stdout, stderr = c.exec_command('docker logs cyberguard_nginx --tail 10 2>&1')
print(stdout.read().decode('utf-8', errors='ignore'))

# Test site
print("\n[5] Testing live site...")
stdin, stdout, stderr = c.exec_command('curl -k -sI https://cyberguardsystem.online/ 2>&1 | head -3')
print(stdout.read().decode('utf-8', errors='ignore'))

c.close()
print("\nDone.")
