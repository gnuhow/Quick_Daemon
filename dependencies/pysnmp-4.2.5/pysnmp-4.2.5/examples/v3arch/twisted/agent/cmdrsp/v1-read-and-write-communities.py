#
# Command Responder
#
# Listen and respond to SNMP GET/SET/GETNEXT queries with
# the following options:
#
# * SNMPv1
# * with SNMP community "public" (read access) or "private" (write access)
# * allow access to SNMPv2-MIB objects (1.3.6.1.2.1)
# * over IPv4/UDP, listening at 127.0.0.1:161
# * using Twisted fraework for network transport
# 
# The following Net-SNMP's commands will GET/SET a value at this Agent:
#
# $ snmpget -v1 -c public 127.0.0.1 SNMPv2-MIB::sysLocation.0
# $ snmpset -v1 -c private 127.0.0.1 SNMPv2-MIB::sysLocation.0 s "far away"
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

# SNMPv1 setup

# SecurityName <-> CommunityName mapping.
# Here we configure two distinct CommunityName's to control read and write
# operations.
config.addV1System(snmpEngine, 'my-read-area', 'public')
config.addV1System(snmpEngine, 'my-write-area', 'private')

# Allow full MIB access for this user / securityModels at VACM
config.addVacmUser(snmpEngine, 1, 'my-read-area', 'noAuthNoPriv', (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 1, 'my-write-area', 'noAuthNoPriv', (1,3,6,1,2,1), (1,3,6,1,2,1))

# Get default SNMP context this SNMP engine serves
snmpContext = context.SnmpContext(snmpEngine)

# Register SNMP Applications at the SNMP engine for particular SNMP context
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)

# Run Twisted main loop
reactor.run()
