import paramiko
import time

for attempt in range(1, 4):
    try:
        print(f"Testing VPS SSH connection (Attempt {attempt}/3)...")
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+', timeout=15)
        
        print("Connected successfully!")
        print("Restarting Nginx to clear upstream cache...")
        stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart nginx')
        stdout.channel.recv_exit_status()

        stdin, stdout, stderr = c.exec_command('curl -k -I https://cyberguardsystem.online/')
        out = stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii')
        print("LIVE HTTPS CHECK:\n", out)
        c.close()
        break
    except Exception as e:
        print(f"Attempt {attempt} error: {e}")
        time.sleep(5)
