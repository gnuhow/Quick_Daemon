#
# GETBULK Command Generator
#
# Send a series of SNMP GETBULK requests
#     with SNMPv2c, community 'public'
#     over IPv4/UDP
#     to an Agent at 195.218.195.228:161
#     with values non-repeaters = 0, max-repetitions = 25
#     for two OIDs in tuple form
#     stop on end-of-mib condition for both OIDs
#
# This script performs similar to the following Net-SNMP command:
#
# $ snmpbulkwalk -v2c -c public -C n0 -C r25 -ObentU 195.218.195.228 1.3.6.1.2.1.1 1.3.6.1.4.1.1
#
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.carrier.asynsock.dgram import udp

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

#
# SNMPv2c setup
#

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public')

# Specify security settings per SecurityName (SNMPv1 - 0, SNMPv2c - 1)
config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 1)

#
# Setup transport endpoint and bind it with security settings yielding
# a target name
#

# UDP/IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode()
)
config.addTargetAddr(
    snmpEngine, 'my-router',
    udp.domainName, ('195.218.195.228', 161),
    'my-creds'
)

# Error/response receiver
def cbFun(sendRequesthandle, errorIndication, errorStatus, errorIndex,
          varBindTable, cbCtx):
    if errorIndication:
        print(errorIndication)
        return  # stop on error
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBindTable[-1][int(errorIndex)-1][0] or '?'
            )
        )
        return  # stop on error
    for varBindRow in varBindTable:
        for oid, val in varBindRow:
            print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))
    return True # signal dispatcher to continue walking

# Prepare initial request to be sent
cmdgen.BulkCommandGenerator().sendReq(
    snmpEngine,
    'my-router',
    0, 25,   # non-repeaters, max-repetitions
    ( ((1,3,6,1,2,1,1), None),
      ((1,3,6,1,4,1,1), None) ),
    cbFun
)

# Run I/O dispatcher which would send pending queries and process responses
snmpEngine.transportDispatcher.runDispatcher()
