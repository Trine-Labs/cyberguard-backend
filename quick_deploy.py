import paramiko, time
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+', timeout=10)
print("Connected!")

sftp = c.open_sftp()
sftp.put(r'd:\CyberGuard\backend\app\routers\settings.py', '/root/cyberguard/backend/app/routers/settings.py')
print("Uploaded settings.py")
sftp.close()

stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart backend celery_worker celery_beat 2>&1')
exit_code = stdout.channel.recv_exit_status()
print(f"Restarted backend (exit={exit_code})")

time.sleep(5)
stdin, stdout, stderr = c.exec_command('curl -k -sI https://cyberguardsystem.online/ 2>&1 | head -1')
print(f"Site: {stdout.read().decode().strip()}")
c.close()
print("Done!")
