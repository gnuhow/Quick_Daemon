#
# Notification Originator
#
# Send SNMP TRAP notification using the following options:
#
# * SNMPv2c
# * with community name 'public'
# * over IPv4/UDP and UDP/IPv6
# * send TRAP notification
# * to two Managers through different network transports
# * with TRAP ID 'coldStart' specified as an OID
# * include managed objects information:
#   1.3.6.1.2.1.1.1.0 = 'Example Notificator'
#   1.3.6.1.2.1.1.5.0 = 'Notificator Example'
#
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp, udp6
from pysnmp.entity.rfc3413 import ntforg, context
from pysnmp.proto.api import v2c

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public', transportTag='all-my-managers')

# Specify security settings per SecurityName (SNMPv2c -> 1)
config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 1)

# Setup transport endpoints and bind it with security settings yielding
# a target name:

# UDP/IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode()
)
config.addTargetAddr(
    snmpEngine, 'my-nms-1',
    udp.domainName, ('127.0.0.1', 162),
    'my-creds',
    tagList='all-my-managers'
)

# UDP/IPv6
config.addTransport(
    snmpEngine,
    udp6.domainName,
    udp6.Udp6SocketTransport().openClientMode()
)
config.addTargetAddr(
    snmpEngine, 'my-nms-2',
    udp6.domainName, ('::1', 162),
    'my-creds',
    tagList='all-my-managers'
)

# Specify what kind of notification should be sent (TRAP or INFORM),
# to what targets (chosen by tag) and what filter should apply to
# the set of targets (selected by tag)
config.addNotificationTarget(
    snmpEngine, 'my-notification', 'my-filter', 'all-my-managers', 'trap'
)

# Allow NOTIFY access to Agent's MIB by this SNMP model (2), securityLevel
# and SecurityName
config.addContext(snmpEngine, '')
config.addVacmUser(snmpEngine, 2, 'my-area', 'noAuthNoPriv', (), (), (1,3,6))

# *** SNMP engine configuration is complete by this line ***

# Create default SNMP context where contextEngineId == SnmpEngineId
snmpContext = context.SnmpContext(snmpEngine)

# Create Notification Originator App instance. 
ntfOrg = ntforg.NotificationOriginator(snmpContext)
 
# Build and submit notification message to dispatcher
ntfOrg.sendNotification(
    snmpEngine,
    # Notification targets
    'my-notification',
    # Trap OID (SNMPv2-MIB::coldStart)
    (1,3,6,1,6,3,1,1,5,1),
    # ( (oid, value), ... )
    ( ((1,3,6,1,2,1,1,1,0), v2c.OctetString('Example Notificator')),
      ((1,3,6,1,2,1,1,5,0), v2c.OctetString('Notificator Example')) )
)

print('Notification is scheduled to be sent')

# Run I/O dispatcher which would send pending message and process response
snmpEngine.transportDispatcher.runDispatcher()
