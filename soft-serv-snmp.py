#PYTHON-SNMP

#! /bin/bash/python2

# Soft-served SNMP
# SNMP 2c,3
# MADE FOR PYTHON 2.7
# Original Author Zachery H Sawyer.
# Platform: Windows.

#import pysnmp
#import wxpython

#  snmptrap -v 3 -a MD5 -A authkey1 -u user1 -l authPriv -x DES -X privkey1 -L o: 10.5.3.10 162 1.3.6.1.6.3.1.1.5.1

# GOALS
# 1. Secure only.
# 2. Simple to use. (I may add auto configure for certain platforms).
# 3. Open source.
# 4. Cross platform.

################ TODO ##################
# SNMP Write to file
# HTTPS Server
# Finish gui, ficking grids
# add a SNMP/HTTPS firewall checker.

from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
from pysnmp import debug

import Tkinter
import ttk
import tkFileDialog
# from Tkinter import tkFileDialog
import datetime

def save_snmp():
        dd='snmp_log'+str(datetime.datetime.today())
        print dd
        filename=tkFileDialog.asksaveasfilename(dd)
        print filename
        print sagent().logs.get()

def open_snmp():
        print "open_snmp"
        filename=tkFileDialog.askopenfilename()
        print filename

def clear_snmp():
        print "clear_snmp"

def sagent():

        ########### INITALIZE THE TTK GUI with frames and NB ###################
        # Root --> frame --> widgets
        root=Tkinter.Tk()
        root.title('Soft Serve IT')
        #root.grid(column=0,row=0,columnspan=2,rowspan=2)
        fmain=ttk.Frame(root,height=1000,width=1000)
        fmain.grid(sticky="NW")
        ftop=ttk.Frame(fmain,height=100)
        ftop.grid(column=0,row=0,columnspan=2,rowspan=1,sticky="N")
        fleft=ttk.Frame(fmain,width=500)
        fleft.grid(column=0,row=1,columnspan=1,rowspan=1,sticky="NW")
        fright=ttk.Frame(fmain,width=2000)
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
        nb.grid(column=0,row=0,sticky='NW')

        
        fsnmp=ttk.Frame(nb)
        fex=ttk.Frame(nb)

        ############## SNMP FRAME ################
        flog=ttk.Frame(nb)
        flog.grid(column=0,row=0,padx=20,pady=20,sticky='NW')

        btn_save=ttk.Button(flog,text='Save',command=save_snmp)
        #btn_save.pack(side=Tkinter.LEFT)
        btn_save.grid(column=0,row=0,columnspan=1,rowspan=1)

        btn_open=ttk.Button(flog,text='Open',command=open_snmp)
        btn_open.grid(column=1,row=0,columnspan=1,rowspan=1)
        #btn_open.pack(side=Tkinter.LEFT)

        btn_clear=ttk.Button(flog,text='Clear',command=clear_snmp)
        btn_clear.grid(column=2,row=0,columnspan=1,rowspan=1)
        #btn_clear.pack(side=Tkinter.LEFT)

        logs=Tkinter.Text(flog, width=100,height=100,yscrollcommand=True,wrap=Tkinter.WORD)
        logs.grid(column=0,row=1,columnspan=7)

        # Instert text example.
        logs.insert(Tkinter.INSERT, "Security is great!")
        print logs

        ############## HTTPS Server Frame ##################
        fhttp=ttk.Frame(nb)
        flog.grid(column=0,row=0,padx=20,pady=20,sticky='NW')


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

        '''
        style.configure("BW.TLabel", foreground="black", background="white")

        style = ttk.Style()
        
        # This is a separator fool
        # left_sep=ttk.Separator(root, orient='vertical')

        # This is a Frame + Label
        # lf=ttk.Labelframe(root, text='Label')

        # This is a notebook.
        n = ttk.Notebook(root)
        f1 = ttk.Frame(n); # first page, which would get widgets gridded into it
        f2 = ttk.Frame(n); # second page
        n.add(f1, text='One')
        n.add(f2, text='Two')

        style.map("C.TButton",
            foreground=[('pressed', 'red'), ('active', 'blue')], \
            background=[('pressed', '!disabled', 'black'), ('active', 'white')] 
            )
        colored_btn = ttk.Button(text="Test", style="C.TButton").pack(fright)
        '''

        root.mainloop()

'''
    # Not using kivy. It doesnt work well with other frameworks.
    from kivy.app import App
    from kivy.uix.button import Button

    kivy.require('1.8.0')

    class sagent(App):
        def build(self):
            return Button(text='Hello World')
                
    sagent().run()
'''
def https_server():
    print "https!"


####### The SNMP Agent Daemon #######

def agent(
    server_ip='127.0.0.1',
    server_port='162',
    snmp_ver='3',
    community='comm1',
    authpriv='11',
    v3auth='sha',
    v3priv='aes128',
    user3='user1',
    authkey3='authkey1',
    privkey3='privkey1',
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

    ############# SNMP VERSION ONE/TWO ###########################
    if snmp_ver=='1':
        config.CommunityData(community, 1)

    if snmp_ver=='2':
        config.CommunityData(community, 2)


    ############## SNMP VERSION THREE IF TREE ################
    if snmp_ver=='3' and authpriv=='00':
        config.addV3User(
             snmpEngine, user3,
             config.NoPrivProtocol,
             config.NoAuthProtocol
        )

    if snmp_ver=='3' and authpriv=='10':
        if v3auth=='md5':
            config.addV3User( 
                snmpEngine,user3,
                config.usmHMACMD5AuthProtocol, authkey3,
                config.NoAuthProtocol
            )

        if v3auth=='sha':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACSHAAuthProtocol, authkey3,
                config.NoAuthProtocol )


    ######## SNMPV3 WITH MD5 AUTH AND PRIV ########
    if snmp_ver=='3' and authpriv=='11':
        if v3auth=='md5' and v3priv=='des':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACMD5AuthProtocol, authkey3,
                config.usmDESPrivProtocol, privkey3
            )

        if v3auth=='md5' and v3priv=='3des':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACMD5AuthProtocol, authkey3,
                config.usm3DESEDEPrivProtocol, privkey3
            )

        if v3auth=='md5' and v3priv=='aes128':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACMD5AuthProtocol, authkey3,
                config.usmAesCfb128Protocol, privkey3
            )

        if v3auth=='md5' and v3priv=='aes192':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACMD5AuthProtocol, authkey3,
                config.usmAesCfb192Protocol, privkey3
            )

        if v3auth=='md5' and v3priv=='aes256':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACMD5AuthProtocol, authkey3,
                config.usmAesCfb256Protocol, privkey3
            )

    #### SHA AUTH ###

        if v3auth=='sha' and v3priv=='des':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACSHAAuthProtocol, authkey3,
                config.usmDESPrivProtocol, privkey3
            )

        if v3auth=='sha' and v3priv=='3des':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACSHAAuthProtocol, authkey3,
                config.usm3DESEDEPrivProtocol, privkey3
            )

        if v3auth=='sha' and v3priv=='aes128':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACSHAAuthProtocol, authkey3,
                config.usmAesCfb128Protocol, privkey3
            )

        if v3auth=='sha' and v3priv=='aes192':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACSHAAuthProtocol, authkey3, 
                config.usmAesCfb192Protocol, privkey3
            )

        if v3auth=='sha' and v3priv=='aes256':
            config.addV3User(
                snmpEngine,user3,
                config.usmHMACSHAAuthProtocol, authkey3,
                config.usmAesCfb256Protocol, privkey3
            )

    # Callback function for receiving notifications
    def cbFun(snmpEngine,
        stateReference,
        contextEngineId, contextName,
        varBinds,cbCtx):
    
        snmpout=open()
        snmpout.write('Notification received, ContextEngineId "%s", ContextName "%s"' % (
            contextEngineId.prettyPrint(), contextName.prettyPrint()))
        for name, val in varBinds:
            snmpout.write('%s = %s' % (name.prettyPrint(), val.prettyPrint()))

    # Register SNMP Application at the SNMP engine
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)

    # this job would never finish
    snmpEngine.transportDispatcher.jobStarted(1) 

    # Run I/O dispatcher which would receive queries and send confirmations
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except:
        snmpEngine.transportDispatcher.closeDispatcher()
    raise

###### This is where main should go ########
if __name__ == '__main__':
    sagent().run()
    save_snmp()

    agent(
        server_ip='10.5.3.10',
        server_port='162',
        snmp_ver='3',
        community='comm1',
        authpriv='11',
        v3auth='sha',
        v3priv='aes128',
        user3='user1',
        authkey3='authkey1',
        privkey3='privkey1',
        engineid3='8000000001020304'
        )
    

