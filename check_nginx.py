import paramiko
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+', timeout=10)

# Check networks
stdin, stdout, stderr = c.exec_command('docker inspect cyberguard_nginx --format "{{json .NetworkSettings.Networks}}" 2>&1')
print('NGINX NETWORKS:', stdout.read().decode('utf-8', errors='ignore')[:600])

stdin, stdout, stderr = c.exec_command('docker inspect cyberguard_backend --format "{{json .NetworkSettings.Networks}}" 2>&1')
print('BACKEND NETWORKS:', stdout.read().decode('utf-8', errors='ignore')[:600])

# Check nginx config file location
stdin, stdout, stderr = c.exec_command('find /root/cyberguard -name "*.conf" 2>/dev/null | head -10')
print('CONF FILES:', stdout.read().decode('utf-8', errors='ignore'))

# Show docker-compose networks section
stdin, stdout, stderr = c.exec_command('grep -A5 "networks" /root/cyberguard/docker-compose.yml | head -30')
print('COMPOSE NETWORKS:', stdout.read().decode('utf-8', errors='ignore'))

c.close()
