import paramiko
import time

for attempt in range(1, 6):
    try:
        print(f"Connecting to VPS (Attempt {attempt}/5)...")
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+', timeout=10)
        
        print("Connected! Restarting Nginx container...")
        stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart nginx')
        stdout.channel.recv_exit_status()

        stdin, stdout, stderr = c.exec_command('curl -k -I https://cyberguardsystem.online/')
        out = stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii')
        print("LIVE HTTPS CHECK:\n", out)
        c.close()
        break
    except Exception as e:
        print(f"Attempt {attempt} failed: {e}")
        time.sleep(3)
