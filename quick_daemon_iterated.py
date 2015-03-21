#! /bin/bash/python2

# Quick Daemon SNMPv3 and HTTPS Server
# Easy graphical tools for sysadmins and network professionals.
# This is intended to be an easy and secure replacement for tftp servers and syslog servers.
# SNMP 3 only

# Primary maintiainer Zachery H Sawyer.
# First release date: 3/14/2015
# Platform: Windows.

# Example client on Centos 7 w/ net-snmp:
# snmptrap -v 3 -a MD5 -A authkey -u user1 -l authPriv -x DES -X privkey1 -L o: 10.5.1.30 162 1.3.6.1.6.3.1.1.5.1
# snmptrap -v 3 -a SHA -A authkey -u user -l authPriv -x AES -X privkey -L o: 10.5.1.156 162 1.3.6.1.6.3.1.1.5.1

# GOALS
# 1. Secure only.
# 2. Simple to use. (I may add auto configure for certain platforms).
# 3. Open source.
# 4. Cross platform.

################ TODO ##################
# SNMP Write to file
# HTTPS Server or SCP transfer
# Log sorting
# Filters.
# add an IP checker
# add a SNMP/SCP/HTTPS firewall/port checker.
# Sanitize inputs.
# Crossplatform install script.
# Mac/Chrome OS testing.
# Clean up the codez + fork the final for a new ui.

import Tkinter
import ttk
import tkFileDialog
import time

import multiprocessing
import os
import subprocess
import paramiko
import socket
import re
import netifaces
import string

class Qdaemon():
    def __init__(self):
        # Get the local IP address.
        # Why is this nearly impossible in Python?
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("gmail.com",80))
        self.outside_ip='10.5.1.156'
        #self.outside_ip=s.getsockname()[0]
        s.close()
        #print netifaces.interfaces()
        if os.name == 'nt':
            self.slash='\\'
        else:
            self.slash='/'

        self.apply_first=False


    def save_snmp(self):
        #dd=str(datetime.datetime.today())
        self.log_path=tkFileDialog.asksaveasfilename()
        self.entry_log_dir.delete(0,254)
        self.entry_log_dir.insert(0,self.log_path)
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


    def startagent(self):
        # python snmp_agent.py 0 10.5.1.156 162 3 comm1 11 SHA AES256 user1 authkey1 privkey1 8000000001020304
        # agent_cmd="python snmp_agent.py "+self.verbose+" "+self.server_ip1+" "+self.server_port1+" "+self.snmp_ver1+" "+self.community1+" "+self.authpriv1+" "+self.v3auth1+" "+self.v3priv1+" "+self.user1+" "+self.authkey1+" "+self.privkey1+" "+self.engineid1

        # Create the file to deal with opening errors.
        log_read=open(self.log_path,'w')
        log_read.close()

        if self.apply_first is False:
            print "Error: please configure and hit apply first."
            return

        if self.verbose==1:
            verb_flag="--verbose"
        else: 
            verb_flag=""

        #snmptrap -v 3 -a SHA -A authkey1 -u user -l authPriv -x AES -X privkey1 -L 10.5.1.156 <engine> <file>
        agent_cmd=string.join(("python snmp_agent.py",verb_flag,
            "-v",str(self.snmp_ver1),
            "-a",str(self.v3auth1),
            "-A",str(self.authkey1),
            "-u",str(self.user1),
            "-l",str(self.authpriv1),
            "-x",str(self.v3priv1),
            "-X",str(self.privkey1),
            "-L",str(self.server_ip1),
            "-e",str(self.engineid1),
            "-f",str(self.log_path)
            ))

        print agent_cmd
        self.snmp_agent=subprocess.Popen(agent_cmd,shell=True,stderr=subprocess.STDOUT)
        # self.gui.update()

        print "Starting event loop."
        self.read_loop_run=True
        self.i=0
        self.log_read=open(self.log_path,'r')
        self.logs.delete(1.0,Tkinter.END)
        self.readloop()
        self.log_read.close()


    def readloop(self):
        if self.read_loop_run is True:
            print "i:", self.i
            self.log_read=open(self.log_path,'r')
            self.logs.delete(1.0,Tkinter.END) 
            self.logs.insert(Tkinter.INSERT, self.log_read.read())
            self.log_read.close()
            self.i=self.i+1
            #self.root.after_idle(self.readloop())
            self.root.after(3000,self.readloop)
        else: 
            print "Exit read loop called."
            return


    def checkagent(self):
        print "polling subprocess: ",self.snmp_agent.poll()


    def stopagent(self):
        self.read_loop_run=False
        print "agent stopped"


    def apply_snmp(self):
        # Sanatize Inputs
        # IP address
        # print self.entry_snmp_ip.get()
        # print re.match([0-9][0-9].[0-9][0-9].[0-9][0-9].[0-9][0-9],self.entry_snmp_ip.get())

        # NEED TO SANATIZE INPUT w/ warning windows
        # self.verbose=self.check_snmp_debug.cget()
        # print self.verbose
        # print self.check_snmp_debug.get()
        self.apply_first=True
        self.verbose=str(self.snmp_debug_state.get())
        self.server_ip1=self.entry_snmp_ip.get()
        self.server_port1=self.entry_snmp_port.get()
        self.snmp_ver1='3'
        self.community1='comm1'
        self.user1=self.entry_snmp_user.get()
        self.authkey1=self.entry_snmp_authkey.get()
        self.privkey1=self.entry_snmp_privkey.get()
        self.engineid1='8000000001020304'
        self.log_path=self.entry_log_dir.get()
        
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
        #print "Saving snmp config to file."

        # Write to a file.
        cfgpath=os.path.dirname(os.path.realpath(__file__))
        cfgpath=cfgpath+self.slash+'qdaemon.cfg'
        self.saveit=open(cfgpath,'w')
        self.saveit.truncate()
        self.saveit.write(str(self.verbose)+',')
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
        #self.root.quit()


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

        btn_start=ttk.Button(flog_top,text='Start Agent',command=self.startagent)
        btn_start.grid(column=3,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        btn_stop=ttk.Button(flog_top,text='Check Agent',command=self.checkagent)
        btn_stop.grid(column=4,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        btn_stop=ttk.Button(flog_top,text='Stop Agent',command=self.stopagent)
        btn_stop.grid(column=5,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        # Flog bottom frame
        flog_bot=ttk.Frame(flog)
        flog_bot.grid(column=0,row=1,sticky='NWES')

        self.logs=Tkinter.Text(flog_bot, width=80,height=30,padx=5,pady=5,wrap=Tkinter.WORD)
        self.log_scrollbar=Tkinter.Scrollbar(flog_bot)       
        self.logs.grid(column=0,row=0,sticky='NWES',padx=0,pady=0)
        self.log_scrollbar.grid(column=1,row=0,sticky='NES',padx=0,pady=0)
        self.log_scrollbar.config(command=self.logs.yview)
        self.logs.config(yscrollcommand=self.log_scrollbar.set)

        # logs insert example       
        self.logs.insert(Tkinter.INSERT, "Security is great!")

        # Insert text example.
        print self.logs

        ############# SNMP config Frame ####################
        fsnmp=ttk.Frame(nb)
        fsnmp.grid(column=0,row=0,padx=20,pady=20,sticky='NWES')

        lbl_snmp_ver=ttk.Label(fsnmp,text='SNMP Version')
        lbl_snmp_ver.grid(column=0,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.combo_snmp_ver=str()
        self.combo_snmp_ver=ttk.Combobox(fsnmp,textvariable=self.combo_snmp_ver)
        self.combo_snmp_ver['values']=('v3')
        self.combo_snmp_ver.grid(column=1,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.combo_snmp_ver.insert(0,'v3') 

        lbl_snmp_ip=ttk.Label(fsnmp,text='Only SNMPv3 is supported.')
        lbl_snmp_ip.grid(column=3,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        lbl_snmp_ip=ttk.Label(fsnmp,text='Agent IP ')
        lbl_snmp_ip.grid(column=0,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.entry_snmp_ip=ttk.Entry(fsnmp)
        self.entry_snmp_ip.grid(column=1,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_snmp_ip.insert(0,self.outside_ip)

        lbl_snmp_ip2=ttk.Label(fsnmp,text='Enter your local IP, ie 192.168.1.10.')
        lbl_snmp_ip2.grid(column=3,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)        

        lbl_snmp_port=ttk.Label(fsnmp,text='Port')
        lbl_snmp_port.grid(column=0,row=2,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.entry_snmp_port=ttk.Entry(fsnmp)
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
        self.combo_snmp_hash.insert(0,'SHA')

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
        self.combo_snmp_crypt.insert(0,'AES128')

        lbl_snmp_crypt2=ttk.Label(fsnmp,text='DES is not secure.')
        lbl_snmp_crypt2.grid(column=3,row=7,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        lbl_snmp_debug=ttk.Label(fsnmp,text="Verbose Debug")
        lbl_snmp_debug.grid(column=0,row=8,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.snmp_debug_state=Tkinter.IntVar()
        self.check_snmp_debug=ttk.Checkbutton(fsnmp,variable=self.snmp_debug_state)
        self.check_snmp_debug.grid(column=1,row=8,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.check_snmp_debug.invoke()
        self.check_snmp_debug.invoke()

        lbl_snmp_debug=ttk.Label(fsnmp,text="SNMP Log Location")
        lbl_snmp_debug.grid(column=0,row=9,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        btn_save=ttk.Button(fsnmp,text='Browse',command=self.save_snmp)
        btn_save.grid(column=1,row=9,columnspan=1,rowspan=1,sticky='NS',padx=5,pady=5)

        default_log_dir=os.path.dirname(os.path.realpath(__file__))+self.slash+"snmp-"+str(time.strftime("%d-%m-%Y-%H-%M-%S"))+".log"
        self.entry_log_dir=ttk.Entry(fsnmp)
        self.entry_log_dir.grid(column=3,row=9,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_log_dir.insert(0,default_log_dir)

        btn_apply=ttk.Button(fsnmp,text='Apply & Save',command=self.apply_snmp)
        btn_apply.grid(column=1,row=10,columnspan=1,rowspan=1,sticky='NWES',padx=10,pady=10)

        ############### Examples ###########################
        fex=ttk.Frame(nb)
        #fex.pack(side=Tkinter.LEFT,expand=True,fill=Tkinter.BOTH)
        fex.grid(column=0,row=0,padx=20,pady=20,sticky='NWES')

        # #ftop.pack(side=Tkinter.TOP,expand=False,fill=Tkinter.X)
        text_fex=Tkinter.Text(fex,padx=5,pady=5,yscrollcommand=True,wrap=Tkinter.WORD)
        #text_fex.pack(side=Tkinter.LEFT,expand=True,fill=Tkinter.BOTH)
        text_fex.grid(column=0,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=0,pady=0)    
        
        examplestr=string.join((
            ' Cisco IOS 12.4',
            'username qdaemon secret 123456', 
            'crypto key generate mod 1024',
            'line vty 0 4',
            'transport input ssh',
            'login local',
            'ip scp server enable',
            'ip scp server enable',
            ' ', 
            'snmp-server group V3Group v3 auth read V3Read write V3Write',
            'snmp-server user <user> V3Group v3 priv sha <authkey> priv AES 256 <privkey>',
            'snmp-server view V3Write iso included',
            'snmp-server view V3Read iso included', 
            'snmp-server host <IP_address> version 3 auth V3User', 
            'snmp-server enable traps all',
            ' ',
            'Cisco ASA',
            'username qdaemon password 123456',
            'crypto key generate mod 1024',
            'ssh <qdaemon_ip>',
            'scp server enable', 
            'scp server enable',
            ' ',
            'Linux, CentOS 7',
            'su',
            'yum install net-snmp',
            'useradd qdaemon password 123456'
            ),'\n')
        text_fex.insert(Tkinter.INSERT,examplestr)
       

        ############## Punchout EVERYTHING #################
        nb.add(fhttp,text='Easy HTTPS')
        nb.add(flog,text='Secure Logs')
        nb.add(fsnmp,text='Configure SNMP Agent')
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
    Qdaemon().gui().run()
    