import paramiko
import sys
import os

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print('Connecting to VPS...')
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

print('Building and restarting containers in background...')
c.exec_command('cd /root/cyberguard && nohup sh -c "docker compose build backend celery_worker celery_beat && docker compose up -d backend celery_worker celery_beat" > /dev/null 2>&1 &')

print('Done.')
c.close()
