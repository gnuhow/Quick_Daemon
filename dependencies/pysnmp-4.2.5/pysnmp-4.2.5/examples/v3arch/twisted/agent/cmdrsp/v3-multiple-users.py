#
# Command Responder
#
# Listen and respond to SNMP GET/SET/GETNEXT/GETBULK queries with
# the following options:
#
# * SNMPv3
# * with USM user 'usr-md5-des', auth: MD5, priv DES or
#   with USM user 'usr-sha-none', auth: SHA, no privacy
#   with USM user 'usr-sha-aes128', auth: SHA, priv AES
# * allow access to SNMPv2-MIB objects (1.3.6.1.2.1)
# * over IPv4/UDP, listening at 127.0.0.1:161
# * using Twisted framework for network transport
# 
# Either of the following Net-SNMP's commands will walk this Agent:
#
# $ snmpwalk -v3 -u usr-md5-des -l authPriv -A authkey1 -X privkey1 localhost .1.3.6
# $ snmpwalk -v3 -u usr-sha-none -l authNoPriv -a SHA -A authkey1 localhost .1.3.6
# $ snmpwalk -v3 -u usr-sha-aes128 -l authPriv -a SHA -A authkey1 -x AES -X privkey1 localhost .1.3.6
#
from twisted.internet import reactor
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.twisted.dgram import udp

# Create SNMP engine with autogenernated engineID and pre-bound
# to socket transport dispatcher
snmpEngine = engine.SnmpEngine()

# Transport setup

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTwistedTransport().openServerMode(('127.0.0.1', 161))
)

# SNMPv3/USM setup

# user: usr-md5-des, auth: MD5, priv DES
config.addV3User(
    snmpEngine, 'usr-md5-des',
    config.usmHMACMD5AuthProtocol, 'authkey1',
    config.usmDESPrivProtocol, 'privkey1'
)
# user: usr-sha-none, auth: SHA, priv NONE
config.addV3User(
    snmpEngine, 'usr-sha-none',
    config.usmHMACSHAAuthProtocol, 'authkey1'
)
# user: usr-sha-none, auth: SHA, priv AES
config.addV3User(
    snmpEngine, 'usr-sha-aes128',
    config.usmHMACSHAAuthProtocol, 'authkey1',
    config.usmAesCfb128Protocol, 'privkey1'
)

# Allow full MIB access for each user at VACM
config.addVacmUser(snmpEngine, 3, 'usr-md5-des', 'authPriv', (1,3,6,1,2,1), (1,3,6,1,2,1)) 
config.addVacmUser(snmpEngine, 3, 'usr-sha-none', 'authNoPriv', (1,3,6,1,2,1), (1,3,6,1,2,1)) 
config.addVacmUser(snmpEngine, 3, 'usr-sha-aes128', 'authPriv', (1,3,6,1,2,1), (1,3,6,1,2,1)) 

# Get default SNMP context this SNMP engine serves
snmpContext = context.SnmpContext(snmpEngine)

# Register SNMP Applications at the SNMP engine for particular SNMP context
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

# Run Twisted main loop
reactor.run()
