import paramiko
import sys
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker ps --format "{{.Names}}: {{.Status}}"')
print('--- Docker PS ---')
print(stdout.read().decode())
stdin, stdout, stderr = c.exec_command('cd /root/cyberguard && docker compose logs celery_worker --tail=20')
print('--- Celery Logs ---')
print(stdout.read().decode())
c.close()
