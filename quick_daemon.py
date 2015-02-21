#! /bin/bash/python2

# Quick Daemon SNMPv3 and HTTPS Server
# Easy graphical tools for sysadmins and network professionals.
# This is intended to be a secure replacement for tftp servers and syslog servers.
# SNMP 3
# MADE FOR PYTHON 2.7
# Primary maintiainer Zachery H Sawyer.
# Platform: Windows.

# Example client on Centos 7 w/ net-snmp:
# snmptrap -v 3 -a MD5 -A authkey1 -u user1 -l authPriv -x DES -X privkey1 -L o: 10.5.3.10 162 1.3.6.1.6.3.1.1.5.1

# GOALS
# 1. Secure only.
# 2. Simple to use. (I may add auto configure for certain platforms).
# 3. Open source.
# 4. Cross platform.

################ TODO ##################
# SNMP Write to file
# HTTPS Server or SCP transfer
# Finish gui, ficking grids
# add a SNMP/SCP/HTTPS firewall checker.
# Add a mini firewall?
# Sanitize inputs.
# Crossplatform install script.
# Mac testing.

from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
from pysnmp import debug

import Tkinter
import ttk
import tkFileDialog
import datetime

import multiprocessing
import BaseHTTPServer, SimpleHTTPServer
import ssl
import os
import paramiko

class Qdaemon():
    def __init__(self):
        print "INITALIZE!"

    def save_snmp(self):
        dd='snmp_log'+str(datetime.datetime.today())
        print dd
        self.log_path=tkFileDialog.asksaveasfilename(dd)
        print self.log_path
        # print sagent().logs.get()
        return

    def open_snmp(self):
        print "open_snmp"
        filename=tkFileDialog.askopenfilename()
        print filename
        return

    def clear_snmp(self):
        print "clear_snmp"
        return
    # Process the snmp config frame inputs.

    ####### The SNMP Agent Daemon #######
    def agent(self,
        server_ip,
        server_port,
        snmp_ver,
        community,
        authpriv,
        v3auth,
        v3priv,
        user3,
        authkey3,
        privkey3,
        engineid3='8000000001020304'
        ):

        server_port=int(server_port)
     
        # Create SNMP engine with autogenernated engineID and pre-bound
        # to socket transport dispatcher
        snmpEngine = engine.SnmpEngine()

        #print type(engineid3), engineid3

        config.addSocketTransport(
            snmpEngine,
            udp.domainName,
            udp.UdpTransport().openServerMode((server_ip, server_port))
        )

        ########################## SNMP VERSION ONE/TWO ###########################
        if snmp_ver=='1':
            config.CommunityData(community, 1)

        if snmp_ver=='2':
            config.CommunityData(community, 2)

        ######################### SNMP VERSION THREE IF TREE ######################
        if snmp_ver=='3' and authpriv=='00':
            config.addV3User(
                 snmpEngine, user3,
                 config.NoPrivProtocol,
                 config.NoAuthProtocol
            )

        if snmp_ver=='3' and authpriv=='10':
            if v3auth=='MD5':
                config.addV3User( 
                    snmpEngine,user3,
                    config.usmHMACMD5AuthProtocol, authkey3,
                    config.NoAuthProtocol
                )

            if v3auth=='SHA':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACSHAAuthProtocol, authkey3,
                    config.NoAuthProtocol)


        ############## SNMPV3 WITH MD5 AUTH AND PRIV ###############
        if snmp_ver=='3' and authpriv=='11':
            if v3auth=='MD5' and v3priv=='DES':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACMD5AuthProtocol, authkey3,
                    config.usmDESPrivProtocol, privkey3
                )

            if v3auth=='MD5' and v3priv=='3DES':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACMD5AuthProtocol, authkey3,
                    config.usm3DESEDEPrivProtocol, privkey3
                )

            if v3auth=='MD5' and v3priv=='AES128':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACMD5AuthProtocol, authkey3,
                    config.usmAesCfb128Protocol, privkey3
                )

            if v3auth=='MD5' and v3priv=='AES192':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACMD5AuthProtocol, authkey3,
                    config.usmAesCfb192Protocol, privkey3
                )

            if v3auth=='MD5' and v3priv=='AES256':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACMD5AuthProtocol, authkey3,
                    config.usmAesCfb256Protocol, privkey3
                )

        #### SHA AUTH ###

            if v3auth=='SHA' and v3priv=='DES':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACSHAAuthProtocol, authkey3,
                    config.usmDESPrivProtocol, privkey3
                )

            if v3auth=='SHA' and v3priv=='3DES':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACSHAAuthProtocol, authkey3,
                    config.usm3DESEDEPrivProtocol, privkey3
                )

            if v3auth=='SHA' and v3priv=='AES128':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACSHAAuthProtocol, authkey3,
                    config.usmAesCfb128Protocol, privkey3
                )

            if v3auth=='SHA' and v3priv=='AES192':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACSHAAuthProtocol, authkey3, 
                    config.usmAesCfb192Protocol, privkey3
                )

            if v3auth=='SHA' and v3priv=='AES256':
                config.addV3User(
                    snmpEngine,user3,
                    config.usmHMACSHAAuthProtocol, authkey3,
                    config.usmAesCfb256Protocol, privkey3
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
            return snmpout
        except:
            print snmpout
            snmpEngine.transportDispatcher.closeDispatcher()
        raise


    def startagent(self):
        #debug.setLogger(debug.Debug('all'))
        x1=self.server_ip
        x2=self.server_port
        x3=self.snmp_ver
        x4=self.community
        x5=self.authpriv
        x6=self.v3auth
        x7=self.v3priv
        x8=self.user3
        x9=self.authkey3
        x10=self.privkey3
        x11=self.engineid3

        print 1,x1
        print 2,x2
        print 3,x3
        print 4,x4
        print 5,x5
        print 6,x6
        print 7,x7
        print 8,x8
        print 9,x9
        print 10,x10
        print 11,x11

        '''
        agent(
            server_ip,
            server_port='162',
            snmp_ver='3',
            community='comm1',
            authpriv='11',
            v3auth='SHA',
            v3priv='AES128',
            user3='user1',
            authkey3='authkey1',
            privkey3='privkey1',
            engineid3='8000000001020304'
            )
        ''' 
        child_agentd,parent_agentd=multiprocessing.Pipe(True)
        self.agentd=multiprocessing.Process(name='quickd',target=self.agent,args=(x1,
            x2,
            x3,
            x4,
            x5,
            x6,
            x7,
            x8,
            x9,
            x10,
            x11))
        
        # logs insert example        
        self.logs.insert(Tkinter.INSERT, "Security is great!")
        
        if not self.agentd.is_alive():
            self.agentd.start()
            print "starting",self.agentd.name, self.agentd.pid
        else: 
            print 'only one process may be started.'

        #child_agentd[0].close()

        try:
            while True:
                print child_agentd
        except:
            print "Finished piping child_agentd."

        #agentd.join()

    def checkagent(self):
        print self.agentd.name, self.agentd.pid, self.agentd.is_alive()

    def stopagent(self):
        self.agentd.terminate()
        print "stopping",self.agentd.name, self.agentd.pid

    def apply_snmp(self):
        self.snmp_ver='3'
        self.community='comm1'
        self.engineid3='8000000001020304'

        # NEED TO SANATIZE INPUT w/ warning windows
        self.user3=self.entry_snmp_user.get()
        self.server_ip=self.entry_snmp_ip.get()
        self.server_port=self.entry_snmp_port.get()

        self.authkey3=self.entry_snmp_authkey.get()
        self.privkey3=self.entry_snmp_privkey.get()
        
        if self.combo_snmp_hash.get() is "noauth" and self.combo_snmp_crypt.get() is not "nopriv":
            print "Must have authentication for private encryption!"

        # This section sets the authpriv='11' based on combo boxes.
        # No sanitization 
        if self.combo_snmp_hash.get() is not "noauth":
            self.v3auth=self.combo_snmp_hash.get()
            if self.combo_snmp_crypt.get() is not "nopriv":
                self.v3priv=self.combo_snmp_crypt.get()
                self.authpriv='11'
            if self.combo_snmp_crypt.get() is "nopriv":
                self.authpriv='10'

        if self.combo_snmp_hash is "noauth":
            self.authpriv='00'

        '''
        print "applying snmp config"
        if self.agentd.is_alive():
            self.stopagent()
            self.startagent()
        else: 
            self.startagent()
            return
        '''

    def reset_snmp(self):
        print "reset snmp configs"

    def gui(self):
        ########### INITALIZE THE TTK GUI with frames and NB ###################
        # Root --> frame --> widgets
        root=Tkinter.Tk()
        root.title('Quick Daemon')
        #root.grid(column=0,row=0,columnspan=2,rowspan=2)
        fmain=ttk.Frame(root,height=1000,width=1000)
        fmain.grid(sticky="NW")
        ftop=ttk.Frame(fmain)
        #ftop.grid(column=0,row=0,columnspan=2,rowspan=1,sticky="N")
        fleft=ttk.Frame(fmain)
        #fleft.grid(column=0,row=1,columnspan=1,rowspan=1,sticky="NW")
        fright=ttk.Frame(fmain)
        fright.grid(column=1,row=1,columnspan=1,rowspan=1,sticky="NW")

        #ftop.pack(side=Tkinter.TOP,expand=False,fill=Tkinter.X)
        #fleft.pack(side=Tkinter.LEFT,expand=False,fill=Tkinter.Y)
        #fright.pack(side=Tkinter.RIGHT,expand=True,fill=Tkinter.BOTH)

        style=ttk.Style()
        ttk.Style().configure("TButton", padding=6, 
            relief="flat", background="#ccc")
        
        lbl1=ttk.Label(ftop,text='TOP')
        lbl1.grid(column=0,row=0)

        lbl2=ttk.Label(fleft,text='LEFT')
        lbl2.grid(column=0,row=0)

        #lbl3=ttk.Label(fright,text='RIGHT')
        #lbl3.grid(column=0,row=0)

        nb=ttk.Notebook(fright)
        nb.grid(column=0,row=0,sticky='NW',padx=10,pady=10) 

        ############## HTTPS Server Frame ##################
        fhttp=ttk.Frame(nb)
        fhttp.grid(column=0,row=0,padx=20,pady=20,sticky='NW')


        ############## SNMP LOG FRAME ################
        flog=ttk.Frame(nb)
        flog.grid(column=0,row=0,padx=20,pady=20,sticky='NW')

        btn_save=ttk.Button(flog,text='Save',command=self.save_snmp)
        btn_save.grid(column=0,row=0,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        btn_open=ttk.Button(flog,text='Open',command=self.open_snmp)
        btn_open.grid(column=1,row=0,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        btn_clear=ttk.Button(flog,text='Clear',command=self.clear_snmp)
        btn_clear.grid(column=2,row=0,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        btn_start=ttk.Button(flog,text='Start Agent',command=self.startagent)
        btn_start.grid(column=3,row=0,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        btn_stop=ttk.Button(flog,text='Check Agent',command=self.checkagent)
        btn_stop.grid(column=4,row=0,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        btn_stop=ttk.Button(flog,text='Stop Agent',command=self.stopagent)
        btn_stop.grid(column=5,row=0,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        self.logs=Tkinter.Text(flog, width=100,height=30,padx=5,pady=5,yscrollcommand=True,wrap=Tkinter.WORD)
        self.logs.grid(column=0,row=1,columnspan=10)

        # Instert text example.
        
        print logs


        ############# SNMP config Frame ####################
        fsnmp=ttk.Frame(nb)
        fsnmp.grid(column=0,row=0,padx=20,pady=20,sticky='NW')

        btn_apply=ttk.Button(fsnmp,text='Apply & Reload',command=self.apply_snmp)
        btn_apply.grid(column=0,row=0,columnspan=1,rowspan=1,sticky='W',padx=10,pady=10)

        btn_apply=ttk.Button(fsnmp,text='Reset',command=self.reset_snmp)
        btn_apply.grid(column=1,row=0,columnspan=1,rowspan=1,sticky='W',padx=10,pady=10)

        lbl_snmp_ip=ttk.Label(fsnmp,text='Only SNMPv3 is supported.')
        lbl_snmp_ip.grid(column=3,row=0,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        lbl_snmp_ip=ttk.Label(fsnmp,text='Agent IP ')
        lbl_snmp_ip.grid(column=0,row=1,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        self.entry_snmp_ip=ttk.Entry(fsnmp)#.set('192.168.1.10')
        self.entry_snmp_ip.grid(column=1,row=1,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)
        self.entry_snmp_ip.insert(0,'10.5.3.10')

        lbl_snmp_ip2=ttk.Label(fsnmp,text='Enter your local IP, ie 192.168.1.10.')
        lbl_snmp_ip2.grid(column=3,row=1,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)        

        lbl_snmp_port=ttk.Label(fsnmp,text='Port')
        lbl_snmp_port.grid(column=0,row=2,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        self.entry_snmp_port=ttk.Entry(fsnmp)#.set('162')
        self.entry_snmp_port.grid(column=1,row=2,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)
        self.entry_snmp_port.insert(0,'162')

        lbl_snmp_port2=ttk.Label(fsnmp,text='Port 162 is default for traps.')
        lbl_snmp_port2.grid(column=3,row=2,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        lbl_snmp_user=ttk.Label(fsnmp,text='Username')
        lbl_snmp_user.grid(column=0,row=3,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        self.entry_snmp_user=ttk.Entry(fsnmp)
        self.entry_snmp_user.grid(column=1,row=3,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)
        self.entry_snmp_user.insert(0,'user1')

        lbl_snmp_pass=ttk.Label(fsnmp,text='Auth Key')
        lbl_snmp_pass.grid(column=0,row=4,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        self.entry_snmp_authkey=ttk.Entry(fsnmp,show='*')
        self.entry_snmp_authkey.grid(column=1,row=4,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)
        self.entry_snmp_authkey.insert(0,'authkey1')

        lbl_snmp_hash=ttk.Label(fsnmp,text='Auth Hash')
        lbl_snmp_hash.grid(column=0,row=5,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        self.combo_snmp_hash_val=str()
        self.combo_snmp_hash=ttk.Combobox(fsnmp,textvariable=self.combo_snmp_hash_val)
        self.combo_snmp_hash['values']=('noauth','MD5','SHA')
        self.combo_snmp_hash.grid(column=1,row=5,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        lbl_snmp_hash2=ttk.Label(fsnmp,text='MD5 is not secure.')
        lbl_snmp_hash2.grid(column=3,row=5,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        lbl_snmp_pass=ttk.Label(fsnmp,text='Priv Key')
        lbl_snmp_pass.grid(column=0,row=6,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        self.entry_snmp_privkey=ttk.Entry(fsnmp,show='*')
        self.entry_snmp_privkey.grid(column=1,row=6,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)
        self.entry_snmp_privkey.insert(0,'privkey1')

        lbl_snmp_crypt=ttk.Label(fsnmp,text='Priv Encryption')
        lbl_snmp_crypt.grid(column=0,row=7,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        self.combo_snmp_crypt_val=str()
        self.combo_snmp_crypt=ttk.Combobox(fsnmp,textvariable=self.combo_snmp_crypt_val)
        self.combo_snmp_crypt['values']=('nopriv','DES','3DES','AES128','AES256')
        self.combo_snmp_crypt.grid(column=1,row=7,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        lbl_snmp_crypt2=ttk.Label(fsnmp,text='DES is not secure.')
        lbl_snmp_crypt2.grid(column=3,row=7,columnspan=1,rowspan=1,sticky='W',padx=5,pady=5)

        ############### Examples ###########################
        fex=ttk.Frame(nb)


        ############## Punchout EVERYTHING #################
        nb.add(fhttp,text='Easy HTTPS')
        nb.add(flog,text='SNMP Logs')
        nb.add(fsnmp,text='Configure SNMPv3')
        nb.add(fex,text='Examples')

        fright.columnconfigure(0, weight=1)
        fright.rowconfigure(0, weight=1)
        nb.columnconfigure(0, weight=1)
        nb.rowconfigure(0, weight=1)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        #nb.pack(side=Tkinter.RIGHT,expand=True,fill=Tkinter.BOTH)

        root.mainloop()

if __name__ == '__main__':
    Qdaemon().gui().run()


'''
comments():
    
    #httpd_process=multiprocessing.Process(target=httpd,args=(server_ip,))
    #httpd_process.start()
    #httpd_process.join()
    # run as a subprocess
    # httpd(server_ip)
    
    #save_snmp()
 
    # use specific flags or 'all' for full debugging
    agent.multiprocessing.Process(target=agent,args=(agent(server_ip,
        server_port='162',
        snmp_ver='3',
        community='comm1',
        authpriv='11',
        v3auth='SHA',
        v3priv='AES128',
        user3='user1',
        authkey3='authkey1',
        privkey3='privkey1',
        engineid3='8000000001020304'
        )))

    agent.start()
    agent.join()
    debug.setLogger(debug.Debug('all'))
    '''
    

'''
    agent(
        server_ip,
        server_port='162',
        snmp_ver='3',
        community='comm1',
        authpriv='11',
        v3auth='SHA',
        v3priv='AES128',
        user3='user1',
        authkey3='authkey1',
        privkey3='privkey1',
        engineid3='8000000001020304'
        )
''' 

