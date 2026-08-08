import paramiko
import sys
import os

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print('Connecting to VPS...')
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

with open(r'd:\CyberGuard\frontend\app\dashboard\components\M365Hub.tsx', 'rb') as f:
    content = f.read()

print(f'Uploading M365Hub.tsx ({len(content)} bytes)...')
stdin, stdout, stderr = c.exec_command('cat > /root/cyberguard/frontend/app/dashboard/components/M365Hub.tsx')
stdin.write(content)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()

print('Rebuilding frontend container...')
c.exec_command('cd /root/cyberguard && nohup sh -c "docker compose build frontend && docker compose up -d frontend" > /dev/null 2>&1 &')

print('Done! Frontend rebuilding in background.')
c.close()
