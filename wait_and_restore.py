import socket
import time
import paramiko

vps_ip = '141.136.44.191'
print(f"Waiting for VPS {vps_ip} to complete reboot and open SSH port 22...")

connected = False
for i in range(1, 15):
    try:
        s = socket.create_connection((vps_ip, 22), timeout=5)
        s.close()
        print(f"SSH port 22 is OPEN on attempt {i}!")
        connected = True
        break
    except Exception as e:
        print(f"Attempt {i}: port 22 not ready ({e}). Retrying in 8s...")
        time.sleep(8)

if connected:
    time.sleep(3)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(vps_ip, username='root', password='.+H@/Dz5jYxtzs,+', timeout=15)
    print("SSH Connected! Bringing up docker compose...")
    stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose up -d')
    stdout.channel.recv_exit_status()
    
    print("Restarting Nginx to clear cache...")
    stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart nginx')
    stdout.channel.recv_exit_status()
    
    stdin, stdout, stderr = c.exec_command('curl -k -I https://cyberguardsystem.online/')
    out = stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii')
    print("LIVE SITE RESPONSE:\n", out)
    c.close()
else:
    print("VPS still starting up.")
