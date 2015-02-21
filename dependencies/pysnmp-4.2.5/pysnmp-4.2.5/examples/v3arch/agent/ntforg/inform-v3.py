#
# Notification Originator
#
# Send SNMP INFORM notification using the following options:
#
# * SNMPv3
# * with user 'usr-md5-none', auth: MD5, priv NONE
# * over IPv4/UDP
# * to a Manager at 127.0.0.1:162
# * send INFORM notification
# * with TRAP ID 'warmStart' specified as an OID
# * include managed object information 1.3.6.1.2.1.1.5.0 = 'system name'
#
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import ntforg, context
from pysnmp.proto.api import v2c

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# Add USM user
config.addV3User(
    snmpEngine, 'usr-md5-none',
    config.usmHMACMD5AuthProtocol, 'authkey1'
)
config.addTargetParams(snmpEngine, 'my-creds', 'usr-md5-none', 'authNoPriv')

# Setup transport endpoint and bind it with security settings yielding
# a target name
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode()
)
config.addTargetAddr(
    snmpEngine, 'my-nms',
    udp.domainName, ('127.0.0.1', 162),
    'my-creds',
    tagList='all-my-managers'
)

# Specify what kind of notification should be sent (TRAP or INFORM),
# to what targets (chosen by tag) and what filter should apply to
# the set of targets (selected by tag)
config.addNotificationTarget(
    snmpEngine, 'my-notification', 'my-filter', 'all-my-managers', 'inform'
)

# Allow NOTIFY access to Agent's MIB by this SNMP model (3), securityLevel
# and SecurityName
config.addContext(snmpEngine, '')
config.addVacmUser(snmpEngine, 3, 'usr-md5-none', 'authNoPriv', (), (), (1,3,6))

# *** SNMP engine configuration is complete by this line ***

# Create default SNMP context where contextEngineId == SnmpEngineId
snmpContext = context.SnmpContext(snmpEngine)

# Create Notification Originator App instance. 
ntfOrg = ntforg.NotificationOriginator(snmpContext)
 
# Error/confirmation receiver
def cbFun(sendRequestHandle, errorIndication, cbCtx):
    print('Notification %s, status - %s' % (
        sendRequestHandle, errorIndication and errorIndication or 'delivered'
      )
    )

# Build and submit notification message to dispatcher
sendRequestHandle = ntfOrg.sendNotification(
    snmpEngine,
    # Notification targets
    'my-notification',
    # Trap OID (SNMPv2-MIB::coldStart)
    (1,3,6,1,6,3,1,1,5,1),
    # ( (oid, value), ... )
    ( ((1,3,6,1,2,1,1,5,0), v2c.OctetString('system name')), ),
    cbFun
)

print('Notification %s scheduled to be sent' % sendRequestHandle)

# Run I/O dispatcher which would send pending message and process response
snmpEngine.transportDispatcher.runDispatcher()
