import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

stdin, stdout, stderr = c.exec_command('docker exec cyberguard_nginx cat /etc/nginx/conf.d/default.conf')
conf = stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii')
print("NGINX CONF:\n", conf)

stdin, stdout, stderr = c.exec_command('docker exec cyberguard_nginx tail -n 20 /var/log/nginx/error.log')
log = stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii')
print("NGINX ERROR LOG:\n", log)

c.close()
