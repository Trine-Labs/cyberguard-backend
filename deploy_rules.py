import paramiko
import sys
import os

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print('Connecting to VPS...')
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

with open(r'd:\CyberGuard\backend\app\services\rules_engine.py', 'rb') as f:
    content = f.read()

print('Uploading rules_engine.py...')
stdin, stdout, stderr = c.exec_command('cat > /root/cyberguard/backend/app/services/rules_engine.py')
stdin.write(content)
stdin.channel.shutdown_write()

exit_status = stdout.channel.recv_exit_status()
if exit_status != 0:
    print('Upload Error:', stderr.read().decode())
    sys.exit(exit_status)

print('Restarting backend and celery_worker...')
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose restart backend celery_worker')
exit_status = stdout.channel.recv_exit_status()
print(stdout.read().decode())
if exit_status != 0:
    print('Restart Error:', stderr.read().decode())
    sys.exit(exit_status)

print('Done.')
c.close()
