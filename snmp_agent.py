from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
from pysnmp import debug

import zerorpc

####### Socket Fun with zerorpc #########
url = "tcp://*:5555"

srv = zerorpc.Server(worker)
srv.bind(url)
srv.run()


####### The SNMP Agent Daemon #######
def agent(self,
    server_ip0,server_port0,
    snmp_ver0,community0,
    authpriv0,v3auth0,v3priv0,
    user0,authkey0,privkey0,
    engineid0='8000000001020304'
    ):

    server_port0=int(server_port0)
 
    # Create SNMP engine with autogenernated engineID and pre-bound
    # to socket transport dispatcher
    snmpEngine = engine.SnmpEngine()

    #print type(engineid3), engineid3

    config.addSocketTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpTransport().openServerMode((server_ip0, server_port0))
    )

    ########################## SNMP VERSION ONE/TWO ###########################
    if snmp_ver0=='1':
        config.CommunityData(community0, 1)

    if snmp_ver0=='2':
        config.CommunityData(community0, 2)

    ######################### SNMP VERSION THREE IF TREE ######################
    if snmp_ver0=='3' and authpriv0=='00':
        config.addV3User(
             snmpEngine, user0,
             config.NoPrivProtocol,
             config.NoAuthProtocol
        )

    if snmp_ver0=='3' and authpriv0=='10':
        if v3auth0=='MD5':
            config.addV3User( 
                snmpEngine,user0,
                config.usmHMACMD5AuthProtocol, authkey0,
                config.NoAuthProtocol
            )

        if v3auth0=='SHA':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACSHAAuthProtocol, authkey0,
                config.NoAuthProtocol)


    ############## SNMPV3 WITH MD5 AUTH AND PRIV ###############
    if snmp_ver0=='3' and authpriv0=='11':
        if v3auth0=='MD5' and v3priv0=='DES':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACMD5AuthProtocol, authkey0,
                config.usmDESPrivProtocol, privkey0
            )

        if v3auth0=='MD5' and v3priv0=='3DES':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACMD5AuthProtocol, authkey0,
                config.usm3DESEDEPrivProtocol, privkey0
            )

        if v3auth0=='MD5' and v3priv0=='AES128':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACMD5AuthProtocol, authkey0,
                config.usmAesCfb128Protocol, privkey0
            )

        if v3auth0=='MD5' and v3priv0=='AES192':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACMD5AuthProtocol, authkey0,
                config.usmAesCfb192Protocol, privkey0
            )

        if v3auth0=='MD5' and v3priv0=='AES256':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACMD5AuthProtocol, authkey0,
                config.usmAesCfb256Protocol, privkey0
            )

    #### SHA AUTH ###

        if v3auth0=='SHA' and v3priv0=='DES':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACSHAAuthProtocol, authkey0,
                config.usmDESPrivProtocol, privkey0
            )

        if v3auth0=='SHA' and v3priv0=='3DES':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACSHAAuthProtocol, authkey0,
                config.usm3DESEDEPrivProtocol, privkey0
            )

        if v3auth0=='SHA' and v3priv0=='AES128':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACSHAAuthProtocol, authkey0,
                config.usmAesCfb128Protocol, privkey0
            )

        if v3auth0=='SHA' and v3priv0=='AES192':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACSHAAuthProtocol, authkey0, 
                config.usmAesCfb192Protocol, privkey0
            )

        if v3auth0=='SHA' and v3priv0=='AES256':
            config.addV3User(
                snmpEngine,user0,
                config.usmHMACSHAAuthProtocol, authkey0,
                config.usmAesCfb256Protocol, privkey0
            )

    # Callback function for receiving notifications
    def cbFun(self,snmpEngine,
        stateReference,
        contextEngineId, contextName,
        varBinds,cbCtx):
    
        global snmpout
        snmpout='Notification received, ContextEngineId "%s", ContextName "%s"' % (
            contextEngineId.prettyPrint(), contextName.prettyPrint())
        for name, val in varBinds:
            snmpout=self.snmpout+'%s = %s' % (name.prettyPrint(), val.prettyPrint())

    # Register SNMP Application at the SNMP engine
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)

    # this job would never finish
    snmpEngine.transportDispatcher.jobStarted(1) 

    # Run I/O dispatcher which would receive queries and send confirmations
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    	print snmpout
        return snmpout
    except:
        print snmpout
        snmpEngine.transportDispatcher.closeDispatcher()
    raise
    

