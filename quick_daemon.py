#! /bin/bash/python2

# Quick Daemon SNMPv3 and HTTPS Server
# Easy graphical tools for sysadmins and network professionals.
# This is intended to be a secure replacement for tftp servers and syslog servers.
# SNMP 3
# MADE FOR PYTHON 2.7
# Primary maintiainer Zachery H Sawyer.
# First release date: 2/22/2015
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
# Finish gui, ficking grids
# HTTPS Server or SCP transfer
# add a SNMP/SCP/HTTPS firewall checker.
# Add a mini firewall?
# Sanitize inputs.
# Crossplatform install script.
# Mac/Chrome OS testing.
# Do the fills right.
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
import os
import paramiko
import socket
import re
import netifaces
import threading
import zerorpc

class Qdaemon():
    def __init__(self):
        # Get the local IP address.
        # Why is this nearly impossible in Python?
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("gmail.com",80))
        self.outside_ip='10.5.3.10'
        #self.outside_ip=s.getsockname()[0]
        s.close()
        #print netifaces.interfaces()

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


    def save_snmp(self):
        dd='snmp_log'+str(datetime.datetime.today())
        #print dd
        self.log_path=tkFileDialog.asksaveasfilename()
        #print self.log_path
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
 
        '''   
    def start_agent_thread(self):
        self.running=True
        print "starting agent thread"
        agentthread=threading.Thread(daemon=True,target=self.agent(self.server_ip1,
            self.server_port1,
            self.snmp_ver1,
            self.community1,
            self.authpriv1,
            self.v3auth1,
            self.v3priv1,
            self.user1,
            self.authkey1,
            self.privkey1,
            self.engineid1))
        agentthread.start()

    def startagent():
        self.agentd=multiprocessing.Process(name='quickd',target=self.agent,args=(
            '10.5.3.10','162','3',
            'comm1','11','SHA','AES128',
            'user1','authkey1','privkey1','8000000001020304'))

        print "starting the agent"
        self.agentd.start()
        print self.agentd.is_alive()
        

        #debug.setLogger(debug.Debug('all'))
        filex=  

        x1=self.server_ip1
        x2=self.server_port1
        x3=self.snmp_ver1
        x4=self.community1
        x5=self.authpriv1
        x6=self.v3auth1
        x7=self.v3priv1
        x8=self.user1
        x9=self.authkey1
        x10=self.privkey1
        x11=self.engineid1

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
        
         agentd=multiprocessing.Process(name='quickd',target=self.agent,args=(
            x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11))
        '''

    def testpipe(self,
        server_ip0,server_port0,
        snmp_ver0,community0,
        authpriv0,v3auth0,v3priv0,
        user0,authkey0,privkey0,
        engineid0='8000000001020304'
        ):
        return "Test is successfully."

    def startagent(self):
        cfgpath=os.path.realpath(__file__)
        cfgpath=cfgpath+'qdaemon.cfg'
        cfg=open(cfgpath,'r')
        cfgread=cfg.read()

        # Parse the text into a list.
        a=0
        y=[]
        x=""
        for i in cfgread:
            if i is not ',':
                x=str(x)+str(i)
            if i is ',':
                y.append(str(x))
                x=""

        #child_agentd,parent_agentd=multiprocessing.Pipe(True) 
        queue=multiprocessing.Queue()
        agentd=multiprocessing.Process(name='quickd',target=self.agent,args=(y[0],y[1],y[2],y[3],y[4],y[5],y[6],y[7],y[8],y[9],y[10]))
        #child_agentd.close()
        # print parent_agentd.recv()

        if agentd.is_alive() is True:
            print 'only one process may be started.'
        else:
            print "starting"
            agentd.start()
            print "agentd started"

        print "agentd.is_alive()",agentd.is_alive()
        #agentd.join()

    def checkagent(self):
        print self.agentd.name, self.agentd.pid, self.agentd.is_alive()


    def stopagent(self):
        self.agentd.terminate()
        print "stopping",self.agentd.name, self.agentd.pid

    
    def apply_snmp(self):
        # Sanatize Inputs
        # IP address
        #print self.entry_snmp_ip.get()
        #print re.match([0-9][0-9].[0-9][0-9].[0-9][0-9].[0-9][0-9],self.entry_snmp_ip.get())

        # NEED TO SANATIZE INPUT w/ warning windows
        self.server_ip1=self.entry_snmp_ip.get()
        self.server_port1=self.entry_snmp_port.get()
        self.snmp_ver1='3'
        self.community1='comm1'
        self.user1=self.entry_snmp_user.get()
        self.authkey1=self.entry_snmp_authkey.get()
        self.privkey1=self.entry_snmp_privkey.get()
        self.engineid1='8000000001020304'
        
        if self.combo_snmp_hash.get() is "noauth" and self.combo_snmp_crypt.get() is not "nopriv":
            print "Must have authentication for private encryption!"

        # This section sets the authpriv='11' based on combo boxes.
        # No sanitization required.
        if self.combo_snmp_hash.get() is not "noauth":
            self.v3auth1=self.combo_snmp_hash.get()
            if self.combo_snmp_crypt.get() is not "nopriv":
                self.v3priv1=self.combo_snmp_crypt.get()
                self.authpriv1='11'
            if self.combo_snmp_crypt.get() is "nopriv":
                self.authpriv1='10'

        if self.combo_snmp_hash is "noauth":
            self.authpriv1='00'

        # Check if the self.agentd object exists in globals.
        if 'self.agentd' in globals():
            print "it exists"
            if self.agentd.is_alive():
                self.stopagent()
                #self.startagent()
            else: 
                print "not alive"
                #self.startagent()
        else:
            #self.startagent()
            print "agentd doesnt exist."
        
        print "applying snmp config"

        # Write to a file.
        cfgpath=os.path.realpath(__file__)
        cfgpath=cfgpath+'qdaemon.cfg'
        self.saveit=open(cfgpath,'w')
        self.saveit.truncate()
        self.saveit.write(self.entry_snmp_ip.get()+',')
        self.saveit.write(self.server_port1+',')
        self.saveit.write('3,')
        self.saveit.write('comm1,')
        self.saveit.write(self.authpriv1+',')
        self.saveit.write(self.v3auth1+',')
        self.saveit.write(self.v3priv1+',')
        self.saveit.write(self.user1+',')
        self.saveit.write(self.authkey1+',')
        self.saveit.write(self.privkey1+',')
        self.saveit.write('8000000001020304,')
        self.saveit.close()
        self.root.quit()


    def reset_snmp(self):
        print "reset snmp configs"


    def gui(self):
        ########### INITALIZE THE TTK GUI with frames and NB ###################
        # Root --> fmain --> fright --> notebook --> widgets
        self.root=Tkinter.Tk()
        self.root.title('Quick Daemon')
        
        #fmain=ttk.Frame(root)
        #fmain.grid(column=0,row=0,sticky="NSEW")

        #ftop=ttk.Frame(fmain)
        #ftop.grid(column=0,row=0,columnspan=2,rowspan=1,sticky="N")
        #ftop.pack(side=Tkinter.TOP,expand=False,fill=Tkinter.X)

        #fleft=ttk.Frame(fmain)
        #fleft.grid(column=0,row=1,columnspan=1,rowspan=1,sticky='NSWE')
        #fleft.pack(side=Tkinter.LEFT,expand=False,fill=Tkinter.Y)

        fright=ttk.Frame(self.root)
        #fright.pack(side=Tkinter.RIGHT,expand=True,fill=Tkinter.BOTH)
        fright.grid(column=0,row=0,columnspan=1,rowspan=1,sticky='NWES')

        #style=ttk.Style()
        #ttk.Style().configure("TButton",padding=6, 
        #    relief="flat", background="#ccc")
        
        #lbl1=ttk.Label(ftop,text='TOP')
        #lbl1.grid(column=0,row=0,sticky='NSWE')

        #lbl2=ttk.Label(fleft,text='LEFT')
        #lbl2.grid(column=0,row=0,sticky='NSWE')

        #lbl3=ttk.Label(fright,text='RIGHT')
        #lbl3.grid(column=0,row=0)

        nb=ttk.Notebook(fright)
        #nb.pack(side=Tkinter.RIGHT,expand=True,fill=Tkinter.BOTH)
        nb.grid(column=0,row=0,padx=10,pady=10,sticky='NWES') 

        ############## HTTPS Server Frame ##################
        fhttp=ttk.Frame(nb)
        fhttp.grid(column=0,row=0,padx=20,pady=20,sticky='NWES')


        ############## SNMP LOG FRAME ################
        flog=ttk.Frame(nb)
        flog.grid(column=0,row=0,sticky='NWES')

        flog_top=ttk.Frame(flog)
        flog_top.grid(column=0,row=0,sticky='NW')

        btn_save=ttk.Button(flog_top,text='Save',command=self.save_snmp)
        btn_save.grid(column=0,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        btn_open=ttk.Button(flog_top,text='Open',command=self.open_snmp)
        btn_open.grid(column=1,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        btn_clear=ttk.Button(flog_top,text='Clear',command=self.clear_snmp)
        btn_clear.grid(column=2,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        #btn_start=ttk.Button(flog_top,text='Start Agent',command=self.start_agent_thread)
        #btn_start.grid(column=3,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        btn_stop=ttk.Button(flog_top,text='Check Agent',command=self.checkagent)
        btn_stop.grid(column=4,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        #btn_stop=ttk.Button(flog_top,text='Stop Agent',command=self.stopagent)
        #btn_stop.grid(column=5,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        # Flog bottom frame
        flog_bot=ttk.Frame(flog)
        flog_bot.grid(column=0,row=1,sticky='NWES')

        self.logs=Tkinter.Text(flog_bot, width=100,height=35,padx=5,pady=5,yscrollcommand=True,wrap=Tkinter.WORD)
        self.logs.grid(column=0,row=0,sticky='NWES',padx=0,pady=0)

        # logs insert example        
        self.logs.insert(Tkinter.INSERT, "Security is great!")

        # Insert text example.
        print self.logs


        ############# SNMP config Frame ####################
        fsnmp=ttk.Frame(nb)
        fsnmp.grid(column=0,row=0,padx=20,pady=20,sticky='NWES')

        btn_apply=ttk.Button(fsnmp,text='Apply & Reload',command=self.apply_snmp)
        btn_apply.grid(column=0,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=10,pady=10)

        btn_apply=ttk.Button(fsnmp,text='Reset',command=self.reset_snmp)
        btn_apply.grid(column=1,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=10,pady=10)

        lbl_snmp_ip=ttk.Label(fsnmp,text='Only SNMPv3 is supported.')
        lbl_snmp_ip.grid(column=3,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        lbl_snmp_ip=ttk.Label(fsnmp,text='Agent IP ')
        lbl_snmp_ip.grid(column=0,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.entry_snmp_ip=ttk.Entry(fsnmp)#.set('192.168.1.10')
        self.entry_snmp_ip.grid(column=1,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_snmp_ip.insert(0,self.outside_ip)

        lbl_snmp_ip2=ttk.Label(fsnmp,text='Enter your local IP, ie 192.168.1.10.')
        lbl_snmp_ip2.grid(column=3,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)        

        lbl_snmp_port=ttk.Label(fsnmp,text='Port')
        lbl_snmp_port.grid(column=0,row=2,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.entry_snmp_port=ttk.Entry(fsnmp)#.set('162')
        self.entry_snmp_port.grid(column=1,row=2,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_snmp_port.insert(0,'162')

        lbl_snmp_port2=ttk.Label(fsnmp,text='Port 162 is default for traps.')
        lbl_snmp_port2.grid(column=3,row=2,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        lbl_snmp_user=ttk.Label(fsnmp,text='Username')
        lbl_snmp_user.grid(column=0,row=3,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.entry_snmp_user=ttk.Entry(fsnmp)
        self.entry_snmp_user.grid(column=1,row=3,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_snmp_user.insert(0,'user1')

        lbl_snmp_pass=ttk.Label(fsnmp,text='Auth Key')
        lbl_snmp_pass.grid(column=0,row=4,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.entry_snmp_authkey=ttk.Entry(fsnmp,show='*')
        self.entry_snmp_authkey.grid(column=1,row=4,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_snmp_authkey.insert(0,'authkey1')

        lbl_snmp_hash=ttk.Label(fsnmp,text='Auth Hash')
        lbl_snmp_hash.grid(column=0,row=5,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.combo_snmp_hash_val=str()
        self.combo_snmp_hash=ttk.Combobox(fsnmp,textvariable=self.combo_snmp_hash_val)
        self.combo_snmp_hash['values']=('noauth','MD5','SHA')
        self.combo_snmp_hash.grid(column=1,row=5,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        lbl_snmp_hash2=ttk.Label(fsnmp,text='MD5 is not secure.')
        lbl_snmp_hash2.grid(column=3,row=5,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        lbl_snmp_pass=ttk.Label(fsnmp,text='Priv Key')
        lbl_snmp_pass.grid(column=0,row=6,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.entry_snmp_privkey=ttk.Entry(fsnmp,show='*')
        self.entry_snmp_privkey.grid(column=1,row=6,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_snmp_privkey.insert(0,'privkey1')

        lbl_snmp_crypt=ttk.Label(fsnmp,text='Priv Encryption')
        lbl_snmp_crypt.grid(column=0,row=7,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.combo_snmp_crypt_val=str()
        self.combo_snmp_crypt=ttk.Combobox(fsnmp,textvariable=self.combo_snmp_crypt_val)
        self.combo_snmp_crypt['values']=('nopriv','DES','3DES','AES128','AES256')
        self.combo_snmp_crypt.grid(column=1,row=7,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        lbl_snmp_crypt2=ttk.Label(fsnmp,text='DES is not secure.')
        lbl_snmp_crypt2.grid(column=3,row=7,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)


        ############### Examples ###########################
        fex=ttk.Frame(nb)
        #fex.pack(side=Tkinter.LEFT,expand=True,fill=Tkinter.BOTH)
        fex.grid(column=0,row=0,padx=20,pady=20,sticky='NWES')

        # #ftop.pack(side=Tkinter.TOP,expand=False,fill=Tkinter.X)
        text_fex=Tkinter.Text(fex,padx=5,pady=5,yscrollcommand=True,wrap=Tkinter.WORD)
        #text_fex.pack(side=Tkinter.LEFT,expand=True,fill=Tkinter.BOTH)
        text_fex.grid(column=0,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=0,pady=0)    
        examplestr=' Cisco IOS 12.4 \n username qdaemon secret 123456 \n crypto key generate mod 1024 \n line vty 0 4 \n  transport input ssh \n  login local \n ip scp server enable \n ip scp server enable \n \n snmp-server group V3Group v3 auth read V3Read write V3Write \n snmp-server user <user> V3Group v3 priv sha <authkey> priv AES 256 <privkey> \n snmp-server view V3Write iso included \n snmp-server view V3Read iso included \n snmp-server host <IP_address> version 3 auth V3User \n snmp-server enable traps all \n \n Cisco ASA \n username qdaemon password 123456 \n crypto key generate mod 1024 \n ssh <qdaemon_ip> \n scp server enable \n scp server enable \n \n Linux, CentOS 7 \n su \n yum install net-snmp \n useradd qdaemon password 123456 \n' 
        text_fex.insert(Tkinter.INSERT,examplestr)
       

        ############## Punchout EVERYTHING #################
        nb.add(fhttp,text='Easy HTTPS')
        nb.add(flog,text='SNMP Logs')
        nb.add(fsnmp,text='Configure SNMPv3')
        nb.add(fex,text='Examples')

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        fright.columnconfigure(0, weight=1)
        fright.rowconfigure(0, weight=1)
        nb.columnconfigure(0, weight=1)
        nb.rowconfigure(0, weight=1)
        fex.columnconfigure(0, weight=1)
        fex.rowconfigure(0, weight=1)
        flog.columnconfigure(0, weight=1)
        flog.rowconfigure(0, weight=0)

        flog.columnconfigure(1, weight=1)
        flog.rowconfigure(1, weight=1)

        flog_top.rowconfigure(0, weight=1, minsize=20)
        flog_top.columnconfigure(0, weight=0, minsize=20)

        flog_bot.columnconfigure(0, weight=1)
        flog_bot.rowconfigure(0, weight=1)

        self.root.mainloop()


if __name__ == '__main__':
    # If a config file exists, start the daemon.
    cfgpath=os.path.realpath(__file__)
    cfgpath=cfgpath+'qdaemon.cfg'
    if os.path.getsize(cfgpath) > 30:
        Qdaemon().startagent()
    
    guid=multiprocessing.Process(name='quickgui',target=Qdaemon().startagent(),args=())
    guid.start()
    guid.join()

    #Qdaemon().gui().run()
    
    

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

