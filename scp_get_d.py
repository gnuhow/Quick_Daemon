# SCP IMPORTS
from paramiko import AutoAddPolicy
from paramiko import SSHClient
from scp import SCPClient
import os
import argparse
import time
import string

def scpget(server_ip,server_port,user,password,local_path,remote_path):
	if os.name == 'nt':
		slash='\\'
	else:
		slash='/'
	ssh = SSHClient()
	ssh.set_missing_host_key_policy(AutoAddPolicy())
	ssh.load_system_host_keys()
	ssh.connect(server_ip,port=int(server_port),username=user,password=password,
	gss_auth=False,gss_deleg_creds=False)
	# except SSHException:
	# except paramiko.ssh_exception.AuthenticationException:
	# SCPCLient takes a paramiko transport as its only argument
	scp=SCPClient(ssh.get_transport())
	scp.get(remote_path,local_path)

if __name__ == '__main__': 
	parser=argparse.ArgumentParser(description='This is a crossplatform scp client based on python and paramiko.')
	parser.add_argument('--verbose','--verb','-v',dest='verbose',
		action='store_true', required=False,help='Verbosity')
	parser.add_argument('-i',dest='server_ip_',action='store',
		required=True,help='SCP server IP')
	parser.add_argument('-p',dest='server_port_',action='store',
		required=False,default='22',help='SCP server IP')
	parser.add_argument('-l',dest='user_',action='store',
		required=True,help='SSH username. May require root.')
	parser.add_argument('-P',dest='password_',action='store',
		required=False,help='SSH Password')
	parser.add_argument('-L',dest='local_path_',action='store',
		required=True,help='Local filepath')    
	parser.add_argument('-r',dest='remote_path_',action='store',
		required=True,help='Remote filepath')   
	parser.add_argument('-q','--quiet',dest='quiet',action='store_true',required=False,help='Disable noisy output.')
	args=parser.parse_args()
	print args.server_ip_,args.server_port_,args.user_,args.password_,args.local_path_,args.remote_path_
	scpget(args.server_ip_,args.server_port_,args.user_,
		args.password_,args.local_path_,args.remote_path_)

	# ARPARSE CANT HANDLE THE ^ CHARACTER!
	# Make sure to log out of any SSH sessions first!
	
	# Debian linux
	# python scp_get_d.py -i 10.5.3.1 -l adm -P ********** -L C:\Users\user\Documents\GitHub\Quick_Daemon\test.xml -r disk0:/dap.xml

	# ASA
	# python scp_get_d.py -i 10.5.3.154 -l root -p ******* -s C:\Users\user\Documents\GitHub\Quick_Daemon\test.c -r /usr/lib/jvm/jdk-8-oracle-arm-vfp-hflt/jre/lib/rt.jar

	# Normal linux client w/ ASA
	# scp get
	# scp.exe -rv adm@10.5.3.1:disk0:/asa825-k8.bin :C:\Users\user\Documents
	
	# scp put
	# scp.exe -rv README.txt adm@10.5.3.1:disk0:/README.txt

