import paramiko
import scp
import os
from contextlib import closing
import urllib
from contextlib import contextmanager


hostname='10.5.3.12'
username='root'
password="1234qwer"
#key_filename=os.path.dirname(os.path.abspath(__file__))+'\\paramiko.key'

ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh_client.connect(hostname, username=username, password=password)

filename=key_filename=os.path.dirname(os.path.abspath(__file__))+'\\test.txt'
scp=paramiko.write(ssh_client.get_transport(), '.')
scp.put(filename)
scp.get(filename)

'''
with closing(write(ssh_client.get_transport(), '.')) as scp:
    scp.send_file(filename, True)
    scp.send_file('../../test.log', remote_filename=filename)

    s = StringIO('this is a test')
    scp.send(s, 'test', '0601', len(s.getvalue()))

with closing(read(ssh_client.get_transport(), '.')) as scp:
    scp.receive(filename)
'''

