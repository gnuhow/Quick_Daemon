
Quick Daemon is intended for receiving logs and transferring files securely with a minimum of setup time. It has an SCP client and a SNMPv3 agent It aims to be cross-platform and is compatible with Cisco, Juniper, Linux, Windows, Apple etc.

Please install Quick Daemon as follows:
	Windows:
	Open the executable available on Github.

	Mac:
	Open the App file available on Github.

	Linux:
	Linux users may install the perquisites with pip and compile from source.

Quick Daemon SNMPv3 and HTTPS Server
Easy graphical tools for network and sysadmin professionals as well as Windows developers.
This is intended to be a secure replacement for tftp and syslog servers.
SNMPv3 only.
MADE FOR PYTHON 2.7
Primary maintainer Zachery H Sawyer.
Client Platform: Windows, OS X, Chrome Linux

Quick Daemon is licensed under the Apache 2.0 licence.
For questions or feedback, contact gnuhow@gmail.com.

----------------SETUP------------------
install windows visual C++ for python 
install python 2.7.9 with links.
easy_install pysnmp
easy_install pysnmp-mibs
easy_install pycrypto
pip install paramiko
pip install Tkinter
pip install scp
pip install netifaces
pip install argparse

---------------Compile---------------
download    http://sourceforge.net/projects/pywin32/files/pywin32
pip install PyInstaller 2.1
pyinstaller <script.py>

# Primary maintiainer Zachery H Sawyer.
# First release date: 4/19/2015 for Windows.

# GOALS
# 1. Secure only.
# 2. Simple to use. (I may add auto configure for certain platforms).
# 3. Open source.
# 4. Cross platform.

################ TODO ##################
# SNMP Write to file
# HTTPS Server or SCP transfer
# Log sorting + Filters
# OID translation
# add a SNMP/SCP/HTTPS firewall/port checker. netst -ano | grep 22
# Crossplatform install script.
# Mac/Chrome OS testing.
# HTTPS PUT reciever, so hard.

