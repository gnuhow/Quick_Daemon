Quick daemon is a SNMPv3 and HTTPS server for receiving logs and transferring files securely with a minimum of setup time. It aims to be cross-platform and should work with Cisco, Juniper, Linux, Windows, Apple etc.

It is liscenced under the Apache liscence.
For questions or feedback, contact gnuhow@gmail.com.

Quick Daemon SNMPv3 and HTTPS Server
Easy graphical tools for sysadmins and network professionals.
This is intended to be a secure replacement for tftp servers and syslog servers.
SNMPv3 only.
MADE FOR PYTHON 2.7
Primary maintiainer Zachery H Sawyer.
Platform: Windows.

 Example client on Centos 7 w/ net-snmp:
snmptrap -v 3 -a MD5 -A authkey1 -u user1 -l authPriv -x DES -X privkey1 -L o: 10.5.3.10 162 1.3.6.1.6.3.1.1.5.1

----------------GOALS------------------
1. Secure only.
2. Simple to use. (I may add auto configure for certain platforms).
3. Open source.
4. Cross platform.

----------------TODO ------------------
SNMP Write to file
HTTPS Server or SCP transfer
Finish gui, ficking grids
add a SNMP/SCP/HTTPS firewall checker.
Add a mini firewall?
Sanitize inputs.
Crossplatform install script.
Mac testing.
