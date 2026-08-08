import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

stdin, stdout, stderr = c.exec_command('curl -k -I https://cyberguardsystem.online/')
out = stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii')
print("LIVE HTTPS CHECK:\n", out)
c.close()
