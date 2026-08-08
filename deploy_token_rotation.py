import paramiko
import sys
import os

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print('Connecting to VPS...')
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

with open(r'd:\CyberGuard\backend\app\tasks\m365_token_rotation.py', 'rb') as f:
    content = f.read()

print('Uploading m365_token_rotation.py...')
stdin, stdout, stderr = c.exec_command('cat > /root/cyberguard/backend/app/tasks/m365_token_rotation.py')
stdin.write(content)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()

print('Restarting celery_worker...')
c.exec_command('cd /root/cyberguard && nohup docker compose restart celery_worker > /dev/null 2>&1 &')

print('Done.')
c.close()
