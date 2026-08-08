import paramiko
import sys

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print('Connecting to VPS...')
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

files_to_upload = [
    (r'd:\CyberGuard\backend\app\services\rules_engine.py', '/root/cyberguard/backend/app/services/rules_engine.py'),
    (r'd:\CyberGuard\backend\app\services\m365_graph_client.py', '/root/cyberguard/backend/app/services/m365_graph_client.py'),
    (r'd:\CyberGuard\backend\app\tasks\m365_token_rotation.py', '/root/cyberguard/backend/app/tasks/m365_token_rotation.py'),
]

for local, remote in files_to_upload:
    with open(local, 'rb') as f:
        content = f.read()
    print(f'Uploading {local.split(chr(92))[-1]} ({len(content)} bytes)...')
    stdin, stdout, stderr = c.exec_command(f'cat > {remote}')
    stdin.write(content)
    stdin.channel.shutdown_write()
    stdout.channel.recv_exit_status()

print('Building and restarting containers...')
stdin, stdout, stderr = c.exec_command(
    'cd /root/cyberguard && docker compose build backend celery_worker && '
    'docker compose up -d backend celery_worker celery_beat && '
    'docker compose exec -T redis redis-cli FLUSHALL'
)
exit_status = stdout.channel.recv_exit_status()
out = stdout.read().decode()
err = stderr.read().decode()
print(out[-500:] if out else '')
if exit_status != 0:
    print('STDERR:', err[-500:])
    sys.exit(exit_status)

print('All done! Containers rebuilt and restarted.')
c.close()
