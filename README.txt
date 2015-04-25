
Quick Daemon is intended for receiving logs and transferring files securely with a minimum of setup time. It has an SCP client and an SNMPv3 agent and works well with the Cisco Router, ASA and Linux.

----------------SETUP------------------
install python 2.7.9 with shortcuts 
install windows visual C++ for python: http://aka.ms/vcpython27
easy_install pycrypto
easy_install pysnmp
easy_install pysnmp-mibs
pip install paramiko
pip install scp
pip install argparse
easy_install netifaces
easy_install crypto
pip install pyinstaller

---------------Compile---------------
Pyinstaller --noupx -F -y --clean -w quick_daemon.py  --icon=<FILE.exe,ID>

pyi-build snmp_agent.py
Pyinstaller -F -w --clean --noupx quick_daemon.py 

-------------snmp_agent.spec------------
# -*- mode: python -*-
import PyInstaller.hooks.hookutils
hiddenimports = ['pysnmp.smi.exval','pysnmp.cache']
a = Analysis(['snmp_agent.py'],
             pathex=['C:\\Users\\user\\Desktop\\qd'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='snmp_agent.exe',
          debug=False,
          strip=None,
          upx=False,
          console=True )


Primary maintiainer Zachery H Sawyer.
First release date: 4/19/2015 for Windows.

