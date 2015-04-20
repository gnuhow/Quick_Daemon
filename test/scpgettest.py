from paramiko import AutoAddPolicy
from paramiko import SSHClient
from scp import SCPClient
import os
import argparse
import time
import string

ssh = SSHClient()
ssh.set_missing_host_key_policy(AutoAddPolicy())
ssh.load_system_host_keys()
ssh.connect('10.5.3.1',port=22,username='adm',password=r'1234qwer%T^Y',
gss_auth=False,gss_deleg_creds=False)
# except SSHException:
# except paramiko.ssh_exception.AuthenticationException:
# SCPCLient takes a paramiko transport as its only argument
scp=SCPClient(ssh.get_transport())
scp.get(r'disk0:/dap.xml',r'C:\Users\user\Documents\GitHub\Quick_Daemon\test.xml')


