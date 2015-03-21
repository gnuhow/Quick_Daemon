
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
from pysnmp import debug

import os
import argparse
import time
import string

####### The SNMP Agent Daemon #######
def agent(verbose,server_ip0,server_port0,
    snmp_ver0,community0,
    authpriv0,v3auth0,v3priv0,
    user0,authkey0,privkey0,filepath0,
    engineid0='8000000001020304'):
    
    if verbose==True:
        debug.setLogger(debug.Debug('all'))

    server_port0=int(server_port0)
    # Create SNMP engine with autogenernated engineID and pre-bound
    # to socket transport dispatcher
    snmpEngine=engine.SnmpEngine()
    #print type(engineid3), engineid3

    config.addSocketTransport(
        snmpEngine,udp.domainName,
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
    def cbFun(snmpEngine,
        stateReference,
        contextEngineId, contextName,
        varBinds,cbCtx):

        saveit=open(filepath0,'a')
        output1=string.join((str(time.strftime("%d/%m/%Y-%H:%M:%S")),
            'Notification received, ContextEngineId',
            'ContextName ',contextEngineId.prettyPrint(),
            contextName.prettyPrint(),'\n'))
        print output1
        saveit.write(output1)

        #print output1
        for name, val in varBinds:
            output2='%s = %s \n' % (name.prettyPrint(), val.prettyPrint())
            saveit.write(output2)
            #print output2
        saveit.close()

    # Register SNMP Application at the SNMP engine
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)
    print "Starting the pysnmp reciever agent."

    # this job would never finish
    snmpEngine.transportDispatcher.jobStarted(1) 

    # Run I/O dispatcher which would receive queries and send confirmations
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except:
        snmpEngine.transportDispatcher.closeDispatcher()
        raise

    #snmptrap -v 3 -a SHA -A authkey1 -u user -l authPriv -x AES -X privkey1 -L o: 10.5.1.156 163 1.3.6.1.6.3.1.1.5.1
    #metavar='verbose',

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description='This is a crossplatform SNMPv1,2c,3 reciever. The syntax is similar to net-snmp. 99 percent of the work should be credited to the pysnmp project.')
    parser.add_argument('--verbose','--verb','-V',action='store_true',
        required=False,help='-v is bound to version.')
    parser.add_argument('-L',dest='server_ip',action='store',
        required=True,default='127.0.0.1',help='Local SNMP reciever IP.')
    parser.add_argument('-p',dest='server_port',action='store',
        required=False,default='162',help='Local SNMP reciever port. Default UDP 162.')
    parser.add_argument('-v',dest='version',action='store',choices=['1', '2c', '3'],
        required=True,help='SNMP version: 1,2c or 3')
    parser.add_argument('-c',dest='community',action='store',
        required=False,default='public',help='Community for v1 and v2c') 
    parser.add_argument('-l',dest='authpriv',action='store',choices=['00','10','11'],
        required=True,help='Enter 11 for AuthPriv or 00 for noAuthnoPriv')
    parser.add_argument('-a',dest='auth_hash',action='store',choices=['MD5','SHA'],
        required=True,help='Hash type: MD5 or SHA')
    parser.add_argument('-x',dest='priv_enc',action='store',choices=['DES','3DES','AES','AES128','AES256'],
        required=True,help='Priv encryption: DES, 3DES, AES128 or AES256')
    parser.add_argument('-u',dest='user',action='store',
        required=True,help='Username')
    parser.add_argument('-A',dest='authkey',action='store',
        required=True,help='Authentication hash key')
    parser.add_argument('-X',dest='privkey',action='store',
        required=True,help='Priv encryption key')
    parser.add_argument('-e',dest='engineid',action='store',
        required=False,help='SNMP engine id')
    parser.add_argument('-f',dest='filepath',action='store',
        required=True,help='File location for storing SNMP trap events.')

    args=parser.parse_args()
    # Default settings.
    if args.server_port=="":
        args.serverport=162
    if args.priv_enc=="AES":
        args.priv_enc=="AES128"
    #print(args.verbose,args.server_ip,args.server_port,args.version,
    #    args.community,args.authpriv,args.auth_hash,args.priv_enc,args.user,
    #    args.authkey,args.privkey,args.filepath,args.engineid)

    agent(args.verbose,args.server_ip,args.server_port,args.version,args.community,args.authpriv,
            args.auth_hash,args.priv_enc,args.user,args.authkey,
            args.privkey,args.filepath,args.engineid)

    # snmptrap -v 3 -a SHA -A authkey1 -u user -l authPriv -x AES -X privkey1 -L o: 10.5.1.156 163 1.3.6.1.6.3.1.1.5.1

    '''
    parser.add_argument('verbose',metavar='verbosity',type=str,help='Ultraverbose mode for debugging.')
    parser.add_argument('server_ip',metavar='server ip',type=str,help='Local Server IP')
    parser.add_argument('server_port',metavar='port',type=str,help='UDP Server Port')
    parser.add_argument('version',type=str,help='SNMP version: 1,2c or 3')
    parser.add_argument('community',metavar='community',type=str,help='Community for SMPv1 and v2')
    parser.add_argument('authpriv',metavar='authpriv',type=str,help='11 for authpriv or 00 for noauthnopriv')
    parser.add_argument('auth_hash',metavar='auth_hash',type=str,help='Hash type: MD5 or SHA')
    parser.add_argument('priv_enc',metavar='priv_enc',type=str,help='Priv encryption: DES, 3DES, AES128 or AES256')
    parser.add_argument('user',metavar='user',type=str,help='Username')
    parser.add_argument('authkey',metavar='authkey',type=str,help='Authentication hash key')
    parser.add_argument('privkey',metavar='privkey',type=str,help='Priv encryption key')
    parser.add_argument('engineid',metavar='engineid',type=str,help='SNMP engine id.')
    '''

