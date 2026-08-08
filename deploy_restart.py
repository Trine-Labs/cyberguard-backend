import paramiko
import sys
import os

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print('Connecting to VPS...')
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

print('Restarting backend and celery_worker in background...')
c.exec_command('cd /root/cyberguard && nohup docker compose restart backend celery_worker > /dev/null 2>&1 &')

print('Done.')
c.close()
