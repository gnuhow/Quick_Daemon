#
# Notification Receiver
#
# Receive SNMP TRAP/INFORM messages with the following options:
#
# * SNMPv1/SNMPv2c
# * with SNMP community "public"
# * over IPv4/UDP, listening at 127.0.0.1:162
#   over IPv4/UDP, listening at 127.0.0.1:2162
# * using Twisted framework for network transport
# * print received data on stdout
# 
# Either of the following Net-SNMP's commands will send notifications to this
# receiver:
#
# $ snmptrap -v2c -c public 127.0.0.1:162 123 1.3.6.1.6.3.1.1.5.1 1.3.6.1.2.1.1.5.0 s test
# $ snmpinform -v2c -c public 127.0.0.1:2162 123 1.3.6.1.6.3.1.1.5.1
#
from twisted.internet import reactor
from pysnmp.entity import engine, config
from pysnmp.carrier.twisted.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv

# Create SNMP engine with autogenernated engineID and pre-bound
# to socket transport dispatcher
snmpEngine = engine.SnmpEngine()

# Transport setup

# UDP over IPv4, first listening interface/port
config.addTransport(
    snmpEngine,
    udp.domainName + (1,),
    udp.UdpTwistedTransport().openServerMode(('127.0.0.1', 162))
)

# UDP over IPv4, second listening interface/port
config.addTransport(
    snmpEngine,
    udp.domainName + (2,),
    udp.UdpTwistedTransport().openServerMode(('127.0.0.1', 2162))
)

# SNMPv1/2c setup

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public')

# Callback function for receiving notifications
def cbFun(snmpEngine,
          stateReference,
          contextEngineId, contextName,
          varBinds,
          cbCtx):
    transportDomain, transportAddress = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
    print('Notification from %s, SNMP Engine %s, Context %s' % (
            transportAddress, contextEngineId.prettyPrint(),
            contextName.prettyPrint()
        )
    )
    for name, val in varBinds:
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
 
# Register SNMP Application at the SNMP engine
ntfrcv.NotificationReceiver(snmpEngine, cbFun)

# Run Twisted main loop
reactor.run()
