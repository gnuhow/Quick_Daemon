#! /bin/bash/python2

# Quick Daemon SNMPv3 and HTTPS Server
# Easy graphical tools for sysadmin and networking professionals.
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
# Log sorting + Filters
# OID translation
# add a SNMP/SCP/HTTPS firewall/port checker. netst -ano | grep 22
# Crossplatform install script.
# Mac/Chrome OS testing.
# HTTPS PUT reciever, so hard.

# GUI IMPORTS
import Tkinter
import ttk
import tkFileDialog
import tkMessageBox
import time

import multiprocessing
import os
import subprocess
import socket
import re
import netifaces
import string

# SCP IMPORTS
from paramiko import SSHClient
from scp import SCPClient


class Qdaemon():
    def __init__(self):
        # Get the local IP address.
        self.localip=[]
        interfaces = netifaces.interfaces()
        for i in interfaces:
            if i == 'lo':
                continue
            iface = netifaces.ifaddresses(i).get(netifaces.AF_INET)
            if iface != None:
                for j in iface:
                    #print j['addr']
                    self.localip.append(j['addr'])


        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("gmail.com",80))
        self.outside_ip=''
        #self.outside_ip=s.getsockname()[0]
        s.close()
        #print netifaces.interfaces()
        if os.name == 'nt':
            self.slash='\\'
        else:
            self.slash='/'
        self.apply_before_agent_start=False


    def scp_local(self):
        return


    def scpvalid(self):
        self.scp_valid=False
        # Validate SCP IP address.
        a=self.entry_scp_ip.get()
        splits=re.split("\.",a)
        #print len(splits)
        if len(splits)!=4:
                self.error_dialog="Please validate the remote IP."
                self.error_message()
                return
        else: 
            for i in splits:
                if len(i)>3:
                    self.error_dialog="Please validate the remote IP."
                    self.error_message()   
                    return         
                if re.match('[0-2][0-9][0-9]',i) != None or re.match('[0-9][0-9]',i) != None or re.match('[0-9]',i) != None:
                    self.scp_ip=a
                else:
                    self.error_dialog="Please validate the remote IP."
                    self.error_message()   
                    return         

        # Validate port.
        check=self.entry_scp_port.get()
        if len(check)>5:
                self.error_dialog="Please enter a correct TCP port."
                self.error_message()   
                return         
        else:
            for a in check:
                if re.match('[0-9]',a) is None:
                    self.error_dialog="Please enter a correct TCP port."
                    self.error_message()
                    return                  
            self.scp_port=self.entry_scp_port.get()

        # Validate user alphanumeric.
        a=self.entry_scp_user.get()
        if len(a)>50:
            self.error_dialog="Please enter an alphanumeric username under 50 characters. Underscore is permitted."
            self.error_message()
            return   
        for i in a:    
            if re.match('\W',a) is not None:
                self.error_dialog="Please enter an alphanumeric username under 50 characters. Underscore is permitted."
                self.error_message()
                return       
            else: self.scp_user=a

        # Validate password
        a=self.entry_scp_pass.get()
        if len(a) > 50 or len(a) <= 6:
            self.error_dialog="Please enter an alphanumeric password under 50 characters and over 6 characters. Underscore is permitted."
            self.error_message()
            return       
        for i in a:   
            if re.match('\W',a) is not None:
                self.error_dialog="Please enter an alphanumeric password under 50 characters and over 6 characters. Underscore is permitted."
                self.error_message()
                return       
            else: self.scp_pass=self.entry_scp_pass.get()

        # Validate local path.
        filename=self.entry_lfile.get()
        a=0
        b=0
        for i in filename:
            a+=1
            if i == self.slash:
                b=a
            if i is '*' or i is '?' or i is '<' or i is '>' or i is '|' or i is '%' or i is '$' or i is '#' or i is '!' or i is "@" or i is "`" or i is "~" or i is "+":
                self.error_dialog="Please enter a valid filename."
                self.error_message()
                return
 
        directory=filename[0:b-1]
        if not os.path.isdir(directory):
            self.error_dialog="That directory does not exist."
            self.error_message()
            return
        self.scp_lfile=filename

        # Validate remote path.
        filename=self.entry_rfile.get()
        a=0
        b=0
        for i in filename:
            a+=1
            if i == self.slash:
                b=a
            if i is '*' or i is '?' or i is '<' or i is '>' or i is '|' or i is '%' or i is '$' or i is '#' or i is '!' or i is "@" or i is "`" or i is "~" or i is "+":
                self.error_dialog="Please enter a valid filename."
                self.error_message()
                return
       
        self.scp_rfile=filename        
        self.scp_valid=True


    def scpput(self): 
        # python scp_put_d.py -i 10.5.3.1 -l adm -P 123456
        #    -L C:\Users\user\Documents\GitHub\Quick_Daemon\AUTHORS.txt -r disk0:/AUTHORS.txt
        #
        # C:\Users\user\Documents\GitHub\Quick_Daemon>python quick_daemon_iterated.py
        # python scpput.py -i 10.5.3.1 -p 22 -l adm -P **** -L C:\Users\user\Documents\GitHub\Quick_Daemon\local.file -r disk0:/remote-name.bin
        # ARPARSE CANT HANDLE THE ^ CHARACTER!
        # Make sure to log out of SSH sessions first!
        self.scpvalid()
        if self.scp_valid is False:
            return
        cmd=string.join(("python scpput.py",
            "-i",str(self.scp_ip),
            "-p",str(self.scp_port),
            "-l",str(self.scp_user),
            "-P",str(self.scp_pass),
            "-L",str(self.scp_lfile),
            "-r",str(self.scp_rfile),
            ))
        
        # Try to run scp command, except with error output into the log.
        try: 
            self.scputd=subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
            # Make a record in the log
            message=string.join(("Secure upload to",
                "user",str(self.scp_user),
                "@",str(self.scp_ip),
                "port",str(self.scp_port),
                "\nLocal File:",str(self.scp_lfile),
                "\nRemote File:",str(self.scp_rfile),
                "\n\n",
                ))
            self.scp_log.insert(Tkinter.INSERT,message)
        except subprocess.CalledProcessError as e:
            #output the last element of the error
            message_=e.output.split('\n')[-2]
            a=0
            b=len(message_)
            for i in message_:
                a+=1
                if i is ":":
                    message=message_[a:b]+"\n\n"
            self.scp_log.insert(Tkinter.INSERT,message)
        return


    def scpget(self):
        # python scp_put_d.py -i 10.5.3.1 -l adm -P 1234qwer 
        #    -L C:\Users\user\Documents\GitHub\Quick_Daemon\AUTHORS.txt -r disk0:/AUTHORS.txt
        #
        # C:\Users\user\Documents\GitHub\Quick_Daemon>python quick_daemon_iterated.py
        # python scpput.py -i 10.5.3.1 -p 22 -l adm -P 1234qwer -L C:\Users\user\Documents\GitHub\Quick_Daemon\local.file -r disk0:/remote-name.bin
        # ARGPARSE CANT HANDLE THE ^ CHARACTER!
        # Make sure to log out of SSH sessions first!
        self.scpvalid()
        if self.scp_valid is False:
            return
        cmd=string.join(("python scpget.py",
            "-i",str(self.scp_ip),
            "-p",str(self.scp_port),
            "-l",str(self.scp_user),
            "-P",str(self.scp_pass),
            "-L",str(self.scp_lfile),
            "-r",str(self.scp_rfile),
            ))
        
        # Try to run scp command, except with error output into the log.
        try: 
            self.scputd=subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
            # Make a record in the log
            message=string.join(("Secure download from",
                "user",str(self.scp_user),
                "@",str(self.scp_ip),
                "port",str(self.scp_port),
                "\nLocal File:",str(self.scp_lfile),
                "\nRemote File:",str(self.scp_rfile),
                "\n\n",
                ))
            self.scp_log.insert(Tkinter.INSERT,message)
        except subprocess.CalledProcessError as e:
            #output the last element of the error
            message_=e.output.split('\n')[-2]
            a=0
            b=len(message_)
            for i in message_:
                a+=1
                if i is ":":
                    message=message_[a:b]+"\n\n"
            self.scp_log.insert(Tkinter.INSERT,message)
        return


    def httpput():
        pass


    def httpget():
        pass

    def snmp_ip_combo(self):
        ip=self.combo_snmp_ip.get()

        return

    def save_snmp(self):
        #dd=str(datetime.datetime.today())
        self.log_path=tkFileDialog.asksaveasfilename()
        self.entry_log_dir.delete(0,254)
        self.entry_log_dir.insert(0,self.log_path)
        #print self.log_path
        return


    def open_snmp(self):
        #print "open_snmp"
        filename=tkFileDialog.askopenfilename()
        print filename
        return


    def clear_snmp(self):
        #print "clear_snmp"
        return


    def startagent(self):
        # python snmp_agent.py 0 10.5.1.156 162 3 comm1 11 SHA AES256 user1 authkey1 privkey1 8000000001020304
        # agent_cmd="python snmp_agent.py "+self.verbose+" "+self.server_ip1+" "+self.server_port1+" "+self.snmp_ver1+" "+self.community1+" "+self.authpriv1+" "+self.v3auth1+" "+self.v3priv1+" "+self.user1+" "+self.authkey1+" "+self.privkey1+" "+self.engineid
        # Create the file to deal with opening errors.

        if self.apply_before_agent_start is False:
            self.error_dialog="Please configure the SNMP agent before starting."
            self.error_message()
            return

        log_read=open(self.log_path,'w')
        log_read.close()

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
            "-f",str(self.log_path),
            '-q',
            ))
        #print agent_cmd
        self.snmp_agent=subprocess.Popen(agent_cmd,shell=True,stderr=subprocess.STDOUT)
        # self.gui.update()
        #print "Starting event loop."
        self.read_loop_run=True
        self.i=0
        self.log_read=open(self.log_path,'r')
        self.logs.delete(1.0,Tkinter.END)
        self.readloop()
        self.log_read.close()


    def configureagent(self):
        self.win_configure=Tkinter.Toplevel(self.root)

        ############# SNMP config Frame ####################
        fsnmp=ttk.Frame(self.win_configure)
        fsnmp.grid(column=0,row=0,padx=0,pady=0,sticky='NWES')

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

        #self.entry_snmp_ip=ttk.Entry(fsnmp)
        #self.entry_snmp_ip.grid(column=1,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        #self.entry_snmp_ip.insert(0,self.outside_ip)

        self.combo_snmp_ip_val=str()
        self.combo_snmp_ip=ttk.Combobox(fsnmp,textvariable=self.combo_snmp_ip_val)
        self.combo_snmp_ip['values']=self.localip
        self.combo_snmp_ip.grid(column=1,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.combo_snmp_ip.insert(0,"")

        lbl_snmp_port=ttk.Label(fsnmp,text='Port')
        lbl_snmp_port.grid(column=0,row=2,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.entry_snmp_port=ttk.Entry(fsnmp)
        self.entry_snmp_port.grid(column=1,row=2,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_snmp_port.insert(0,'162')

        lbl_snmp_port2=ttk.Label(fsnmp,text='Port 162 is default for SNMP traps.')
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
        self.entry_log_dir=ttk.Entry(fsnmp,width=90)
        self.entry_log_dir.grid(column=0,row=10,columnspan=99,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_log_dir.insert(0,default_log_dir)

        btn_apply=ttk.Button(fsnmp,text='Apply & Save',command=self.apply_snmp)
        btn_apply.grid(column=1,row=11,columnspan=1,rowspan=1,sticky='NS',padx=10,pady=10)


    def readloop(self):
        if self.read_loop_run is True:
            self.log_read=open(self.log_path,'r')
            self.logs.delete(1.0,Tkinter.END) 
            size=os.path.getsize(self.log_path)
            if size > 100000000:
                self.log_read.seek(-100000001,2)
                self.logs.insert(1.0, self.log_read.read(100000000))
            else: self.logs.insert(1.0, self.log_read.read())
            self.log_read.close()
            self.i=self.i+1
            autoscroll=self.autoscroll_state.get()
            if autoscroll is 1: self.logs.yview(Tkinter.END)
            self.root.after(3000,self.readloop)
            #print "i:", self.i
            #self.root.after_idle(self.readloop())
        else: 
            #print "Agent stopped, Exiting read loop."
            return


    def checkagent(self):
        self.error_dialog="polling subprocess: "+self.snmp_agent.poll()+"\nread_loop_run" +self.read_loop_run
        self.error_message()


    def stopagent(self):
        self.read_loop_run=False
        try:
            self.snmp_agent.kill()
            self.error_dialog="Agent Stopped"
            self.error_message()
        except:
            self.error_dialog="Unable to stop the agent."
            self.error_message()


    def error_message(self):
        tkMessageBox.showerror("Error Message", self.error_dialog)


    def apply_snmp(self):
        # Validate Inputs
        # IP address
        # print self.entry_snmp_ip.get()
        # 
        # NEED TO SANATIZE INPUT w/ warning windows
        # self.verbose=self.check_snmp_debug.cget()
        # print self.verbose
        # print self.check_snmp_debug.get()

        self.verbose=str(self.snmp_debug_state.get())

        # Validate IP address.
        splits=re.split("\.",self.combo_snmp_ip.get())
        #print len(splits)
        if len(splits)!=4:
                self.error_dialog="Please validate the SNMP IP."
                self.error_message()
                return
        else: 
            for a in splits:
                if len(a)>3:
                    self.error_dialog="Please validate the SNMP IP."
                    self.error_message()   
                    return         
                if re.match('[0-2][0-9][0-9]',a) != None or re.match('[0-9][0-9]',a) != None or re.match('[0-9]',a) != None:
                    self.server_ip1=self.combo_snmp_ip.get()
                else:
                    self.error_dialog="Please validate the SNMP IP."
                    self.error_message()   
                    return         
        
        # Validate port.
        check=self.entry_snmp_port.get()
        if len(check)>5:
                self.error_dialog="Please validate the SNMP Server Port."
                self.error_message()   
                return         
        else:
            for a in check:
                if re.match('[0-9]',a) is None:
                    self.error_dialog="Please validate the SNMP Server Port."
                    self.error_message()
                    return                  
            self.server_port1=self.entry_snmp_port.get()
        
        # Validate Version.
        self.snmp_ver1='3'

        # Validate Community.
        self.community1='comm1'

        # Validate user alphanumeric.
        a=self.entry_snmp_user.get()
        if len(a)>50:
            self.error_dialog="Please enter an alphanumeric username under 50 characters. Underscore is permitted."
            self.error_message()
            return       
        if re.match('\W',a) is not None:
            self.error_dialog="Please enter an alphanumeric username under 50 characters. Underscore is permitted."
            self.error_message()
            return       
        else: self.user1=self.entry_snmp_user.get()
        
        # Validate authkey
        a=self.entry_snmp_authkey.get()
        if len(a) > 50 or len(a) <= 6:
            self.error_dialog="Please enter an alphanumeric authkey under 50 characters and over 6 characters. Underscore is permitted."
            self.error_message()
            return       
        for i in a: 
            if re.match('\W',a) is not None:
                self.error_dialog="Please enter an alphanumeric authkey under 50 characters and over 6 characters. Underscore is permitted."
                self.error_message()
                return       
            else: self.authkey1=self.entry_snmp_authkey.get()

        # Validate privkey
        a=self.entry_snmp_privkey.get()
        if len(a) > 50 or len(a) <= 6:
            self.error_dialog="Please enter an alphanumeric authkey under 50 characters and over 6 characters. Underscore is permitted."
            self.error_message()
            return       
        for i in a: 
            if re.match('\W',a) is not None:
                self.error_dialog="Please enter an alphanumeric authkey under 50 characters and over 6 characters. Underscore is permitted."
                self.error_message()
                return       
            else: self.privkey1=self.entry_snmp_privkey.get()

        self.engineid1='8000000001020304'
        
        # Validate logfile path.
        filename=self.entry_log_dir.get()
        a=0
        b=0
        for i in filename:
            a+=1
            if i == self.slash:
                b=a
            if i is '*' or i is '?' or i is '<' or i is '>' or i is '|' or i is '%' or i is '$' or i is '#' or i is '!' or i is "@" or i is "`" or i is "~" or i is "+":
                self.error_dialog="Please enter a valid filename."
                self.error_message()
                return
        
        directory=filename[0:b]
        if not os.path.isdir(directory):
            self.error_dialog="That directory does not exist."
            self.error_message()
            return
        else:
            try:
                test=open(filename, 'w').close()
                os.unlink(filename)
            except OSError:
                self.error_dialog="Please enter a valid filename."
                self.error_message()
                return

        if self.combo_snmp_hash.get() is "noauth" and self.combo_snmp_crypt.get() is not "nopriv":
            self.error_dialog="Authentication is required for encryption."
            self.error_message()
            return
        self.log_path=filename

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
        self.apply_before_agent_start=True
        self.win_configure.destroy()

        '''
        # Write to a file. Not a good idea to saving is passwords in cleartext.
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
        '''


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

        ################### SCP Client Frame ##############
        frame_scp=ttk.Frame(nb)
        frame_scp.grid(column=0,row=0,padx=20,pady=20,sticky='NWES')

        lbl_scp_user=ttk.Label(frame_scp,text='Username')
        lbl_scp_user.grid(column=0,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.entry_scp_user=ttk.Entry(frame_scp)
        self.entry_scp_user.grid(column=1,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)


        lbl_scp_pass=ttk.Label(frame_scp,text='Password')
        lbl_scp_pass.grid(column=2,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)        

        self.entry_scp_pass=ttk.Entry(frame_scp,show='*')
        self.entry_scp_pass=ttk.Entry(frame_scp)
        self.entry_scp_pass.grid(column=3,row=1,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        lbl_scpip=ttk.Label(frame_scp,text='Remote IP')
        lbl_scpip.grid(column=0,row=2,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.entry_scp_ip=ttk.Entry(frame_scp)
        self.entry_scp_ip.grid(column=1,row=2,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        lbl_scp_port=ttk.Label(frame_scp,text='Remote Port')
        lbl_scp_port.grid(column=2,row=2,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)        

        self.entry_scp_port=ttk.Entry(frame_scp)
        self.entry_scp_port.grid(column=3,row=2,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_scp_port.insert(0,'22')

        lbl_scp_rfile=ttk.Label(frame_scp,text='Remote filepath:')
        lbl_scp_rfile.grid(column=0,row=3,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)  

        self.entry_rfile=ttk.Entry(frame_scp)
        self.entry_rfile.grid(column=1,row=3,columnspan=3,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_rfile.insert(0,'disk0:/remote-name.bin')        

        lbl_scp_lfile=ttk.Label(frame_scp,text='Local filepath:')
        lbl_scp_lfile.grid(column=0,row=4,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)  

        scp_btn_save=ttk.Button(frame_scp,text='Browse',command=self.scp_local)
        scp_btn_save.grid(column=0,row=5,columnspan=1,rowspan=1,sticky='NS',padx=5,pady=5)

        scp_default_local=os.path.dirname(os.path.realpath(__file__))+self.slash+"local.file"
        self.entry_lfile=ttk.Entry(frame_scp)
        self.entry_lfile.grid(column=1,row=4,columnspan=3,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.entry_lfile.insert(0,scp_default_local) 

        scp_btn_save=ttk.Button(frame_scp,text='Upload',command=self.scpput)
        scp_btn_save.grid(column=1,row=5,columnspan=1,rowspan=1,sticky='NS',padx=5,pady=5)

        scp_btn_save=ttk.Button(frame_scp,text='Download',command=self.scpget)
        scp_btn_save.grid(column=2,row=5,columnspan=1,rowspan=1,sticky='NS',padx=5,pady=5)

        frame_scp_log=ttk.Frame(frame_scp)
        frame_scp_log.grid(column=0,row=99,sticky='NWES',columnspan=99)

        self.scp_log=Tkinter.Text(frame_scp_log, width=80,height=30,padx=5,pady=5,wrap=Tkinter.WORD)
        self.scp_log_scrollbar=Tkinter.Scrollbar(frame_scp_log)
        self.scp_log.grid(column=0,row=0,sticky='NWES',padx=0,pady=0,columnspan=1)
        self.scp_log_scrollbar.grid(column=1,row=0,sticky='NES',padx=0,pady=0)
        self.scp_log_scrollbar.config(command=self.scp_log.yview)
        self.scp_log.config(yscrollcommand=self.scp_log_scrollbar.set) 
        self.scp_log.insert(Tkinter.INSERT, "This is the SCP file transfer history. \n\n")

        ############## HTTPS Server Frame ##################
        #fhttp=ttk.Frame(nb)
        #fhttp.grid(column=0,row=0,padx=20,pady=20,sticky='NWES')

        ############## SNMP LOG FRAME ################
        flog=ttk.Frame(nb)
        flog.grid(column=0,row=0,sticky='NWES')

        flog_top=ttk.Frame(flog)
        flog_top.grid(column=0,row=0,sticky='NW')

        btn_start=ttk.Button(flog_top,text='2) Start Agent',command=self.startagent)
        btn_start.grid(column=3,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        btn_stop=ttk.Button(flog_top,text='3) Check Agent',command=self.checkagent)
        btn_stop.grid(column=4,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        btn_stop=ttk.Button(flog_top,text='4) Stop Agent',command=self.stopagent)
        btn_stop.grid(column=5,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        self.autoscroll_state=Tkinter.IntVar()
        self.check_autoscroll=ttk.Checkbutton(flog_top,text='Auto Scroll',variable=self.autoscroll_state)
        self.check_autoscroll.grid(column=7,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)
        self.check_autoscroll.invoke()

        btn_stop=ttk.Button(flog_top,text='1) Configure',command=self.configureagent)
        btn_stop.grid(column=2,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=5,pady=5)

        # Flog bottom frame
        flog_bot=ttk.Frame(flog)
        flog_bot.grid(column=0,row=1,sticky='NWES',columnspan=99)

        self.logs=Tkinter.Text(flog_bot, width=80,height=30,padx=5,pady=5,wrap=Tkinter.WORD)
        self.log_scrollbar=Tkinter.Scrollbar(flog_bot)       
        self.logs.grid(column=0,row=0,sticky='NWES',padx=0,pady=0,columnspan=99)
        self.log_scrollbar.grid(column=1,row=0,sticky='NES',padx=0,pady=0)
        self.log_scrollbar.config(command=self.logs.yview)
        self.logs.config(yscrollcommand=self.log_scrollbar.set)

        # logs insert example       
        self.logs.insert(Tkinter.INSERT, "SNMPv3 Messages will appear here.")

        # Insert text example.
        # print self.logs

        ############### Examples ###########################
        fex=ttk.Frame(nb)
        #fex.pack(side=Tkinter.LEFT,expand=True,fill=Tkinter.BOTH)
        fex.grid(column=0,row=0,padx=20,pady=20,sticky='NWES')

        #ftop.pack(side=Tkinter.TOP,expand=False,fill=Tkinter.X)
        self.text_fex=Tkinter.Text(fex,padx=5,pady=5,yscrollcommand=True,wrap=Tkinter.WORD)
        #text_fex.pack(side=Tkinter.LEFT,expand=True,fill=Tkinter.BOTH)
        self.text_fex.grid(column=0,row=0,columnspan=1,rowspan=1,sticky='NWES',padx=0,pady=0)       
        self.examplestr=string.join((
            'Cisco IOS 12.4 SCP Server',
            'username qdaemon secret 123456', 
            'crypto key generate mod 1024',
            'line vty 0 4',
            'transport input ssh',
            'login local',
            'ip scp server enable',
            ' ', 
            'Cisco IOS 12.4 with SNMPv3',
            'snmp-server group qdaemon v3 priv read',
            'snmp-server user <user> <V3Group> v3 auth sha <authkey> priv AES 128 <privkey>',
            'snmp-server view V3Write iso included',
            'snmp-server view V3Read iso included', 
            'snmp-server host <IP_address> version 3 auth V3User', 
            'snmp-server enable traps all',
            ' ',
            'Cisco ASA SCP Server',
            'username <user> password <pass>',
            'crypto key generate mod 1024',
            'ssh <qdaemon local ip>',
            'scp server enable', 
            ' ',
            'Cisco ASA with SNMPv3 authPriv',
            'snmp-server group qdaemon v3 priv read',
            'snmp-server user <user> qdaemon v3 auth sha <authkey1> priv AES 128 <privkey1>',
            'snmp-server host <interface> <agent-ip> version 3 <user> udp-port 162',
            'snmp-server contact <email>',
            'snmp-server enable traps all',
            'snmp-server enable traps syslog',
            # Set the logging level; 0 is critical and 7 is debugging.
            'logging history <0-7>',
            ' ',
            'Linux CentOS 7 SNMPv3 Trap',
            'su',
            'yum install net-snmp',
            'useradd qdaemon',
            'snmptrap -v 3 -a SHA -A <authkey1> -u <user1> -l authPriv -x AES -X privkey1 -L o: <agent ip> 162 1.3.6.1.6.3.1.1.5.1 '
            '# engineID 8000000001020304'
            ' ',
            'Linux CentOS 7 SCP Server',
            'yum install openssh',
            'useradd qdaemon',
            'service openssh start',
            ),'\n')

        self.text_fex.insert(Tkinter.INSERT,self.examplestr)       
        self.fex_scrollbar=Tkinter.Scrollbar(fex)       
        self.fex_scrollbar.grid(column=1,row=0,sticky='NES',padx=0,pady=0)
        self.fex_scrollbar.config(command=self.text_fex.yview)
        self.text_fex.config(yscrollcommand=self.fex_scrollbar.set)


        ############## Punchout EVERYTHING #################
        nb.add(frame_scp,text="SCP File Transfer")
        #nb.add(fhttp,text='HTTPS Files')
        nb.add(flog,text='Secure SNMPv3 Logs')
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

        try:
            self.root.mainloop()
        except:
            self.read_loop_run=False
            self.snmp_agent.kill()

if __name__ == '__main__':
    Qdaemon().gui().run()
 

 #------------snmp agent import for compiler----------
import snmp_agent
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
from pysnmp import debug

import os
import argparse
import time
import string
import pycrypto
import crypto
import scp

#--------------scp import for compiler ------------------
from paramiko import AutoAddPolicy
from paramiko import SSHClient
from scp import SCPClient
import os
import argparse
import time
import string



