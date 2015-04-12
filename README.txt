Quick daemon is a SNMPv3 and HTTPS server for receiving logs and transferring files securely with a minimum of setup time. It aims to be cross-platform and should work with Cisco, Juniper, Linux, Windows, Apple etc.

Please install Quick Daemon as follows:

Windows:
Open the executable available on Github.

Mac:
Open the App file available on Github.

Linux:
Linux users may install the perquisites with pip and compile from source.

It is licensed under the Apache 2.0 licence.
For questions or feedback, contact gnuhow@gmail.com.

Quick Daemon SNMPv3 and HTTPS Server
Easy graphical tools for network and sysadmin professionals as well as Windows developers.
This is intended to be a secure replacement for graphical tftp and syslog servers.
SNMPv3 only.
MADE FOR PYTHON 2.7
Primary maintainer Zachery H Sawyer.
Platform: Windows, OS X, Linux

Example client on Centos 7 w/ net-snmp:
snmptrap -v 3 -a MD5 -A authkey1 -u user1 -l authPriv -x DES -X privkey1 -L o: 10.5.3.10 162 1.3.6.1.6.3.1.1.5.1


----------------GOALS------------------
1. Secure only.
2. Simple to use. (I may add auto configure for certain platforms).
3. Open source.
4. Cross platform.


----------------TODO ------------------
Autoconnect scree
Easy way to Apply configs fist
IP check
HTTPS Server or SCP transfer
add a SNMP/SCP/HTTPS firewall checker.
Crossplatform install script.
Mac testing.


----------------SETUP------------------
install windows C++ for python
install python 2.7.9 with links.
easy_install pysnmp
easy_install pysnmp-mibs
easy_install pycrypto
pip install paramiko
pip install zerorpc
pip install scp


---------------Compile---------------
download    http://sourceforge.net/projects/pywin32/files/pywin32
pip install PyInstaller 2.1
pyinstaller <script.py>


