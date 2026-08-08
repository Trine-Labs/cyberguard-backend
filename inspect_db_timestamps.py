import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('141.136.44.191', username='root', password='.+H@/Dz5jYxtzs,+')

stdin, stdout, stderr = c.exec_command('docker exec cyberguard_backend pwd && docker exec cyberguard_backend ls -la')
print("PWD/LS:\n", stdout.read().decode())
c.close()
