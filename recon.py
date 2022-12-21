# 

# TODO 
# Research python intersection() method for easier service port grouping

#!/bin/python3

import os
import re
import subprocess
import ipaddress
import requests
import glob
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-target', metavar='IP/Domain', type=str, help='IP Address or Domain')
parser.add_argument('-target_list', metavar='hosts.lst', type=str, help='List of IP Addresses and/or Domains')
parser.add_argument('-p', metavar='Port(s)', type=str, help='Service Ports')

args = parser.parse_args()


#Create Directory for target and move target list into new directory and cd into directory for rest of script
os.system('mkdir ' + args.target)
#os.system('mv ' + args.target_list + ' ' + args.target)
os.chdir(args.target)

ports = args.p.replace(',', ' ').split()
for port in ports:

    # SSH
    if port in['22','2222']:
        os.system('cp /opt/SSHScan/config.yml .')
        os.system('nmap -p ' + port + ' -oN ssh-nmap-' + port + '.txt -Pn --open --script="banner,ssh-hostkey,ssh-auth-methods" ' + args.target)
        os.system('python3 /opt/SSHScan/sshscan.py -t ' + args.target + ':' + port + ' > sshscan.txt')
        os.system('ssh-audit --level=warn ' + args.target + ':' + port + ' > ssh-audit-' + port + '.txt')
        os.system('ssh-keyscan -t rsa ' + args.target + ' ' + port + ' > ssh-keyscan-' + port + '.txt')
    #   os.system('msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS ' + args.target + '; set RPORT 22; run; exit" && msfconsole -q -x "use scanner/ssh/ssh_enumusers; set RHOSTS ' + args.target + '; set RPORT 22; run; exit" && msfconsole -q -x "use auxiliary/scanner/ssh/juniper_backdoor; set RHOSTS ' + args.target + '; set RPORT 22; run; exit"')

    # SMTP
    if port in ['25']:
        os.system('sudo nmap --script=smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-open-relay,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 ' + args.target + ' -Pn -oN smtp-scan -vvv')

    # WhatWeb
    if port in ['80' , '3080' , '4080' , '5080' , '5357' , '5985' , '6080' , '7080' , '8080','13080']:
        os.system('whatweb -a 3 http://' + args.target + ':' + port + ' > whatweb-' + port +'.txt')

    if port in ['443' , '943']:
        os.system('whatweb -a 3 https://' + args.target + ':' + port + ' > whatweb-' + port +'.txt')

    # SSLScan
    if port in ['443' , '943']:
        os.system('sslscan ' + args.target + ':' + port + ' > sslscan-' + port + '.txt')


    # TestSSL
    if port in ['443' , '943']:
        os.system('/opt/testssl.sh/testssl.sh ' + args.target + ':' + port + ' > testssl-' + port + '.txt')
    
    # HTTP Nmap
    if port in ['80']: #, '443', '943', '3080' , '4080' , '5080' , '5357' , '5985' , '6080' , '7080' , '8080','13080']:
        os.system('nmap -v -oN http-nmap.txt --open --reason -Pn -sV -p 80,443,943,3080,4080,5080,5357,5985,6080,7080,8080,13080 --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" ' + args.target)
    if port in ['80']: #, '443', '943', '3080' , '4080' , '5080' , '5357' , '5985' , '6080' , '7080' , '8080','13080']:
        os.system('nmap -v -oN http-aggr.nmap --open --reason -Pn -sV -p 80,443,943,3080,4080,5080,5357,5985,6080,7080,8080,13080 -A ' + args.target)

    # Web Fuzz
        #os.system('ffuf -u https://' + args.target + '/FUZZ -r -c -v -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt > webfuzz.txt')
        #os.system('gobuster dir -u http://' + args.target + ' -k -t 50 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --exclude-length 0 > webfuzz.txt')
        #os.system('gobuster dir -u https://' + args.target + ' -k -t 50 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --exclude-length 0 > webfuzz-443.txt')
        #os.system('gobuster dir -u https://' + args.target + ':943 -k -t 50 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --exclude-length 0 > webfuzz-943.txt')
    if port in ['80' , '3080' , '4080' , '5080' , '5357' , '5985' , '6080' , '7080' , '8080' , '13080']:
        os.system('feroxbuster -u http://' + args.target + ':' + port + ' -t 50 -k -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -e -r -v -n -o webfuzz-' + port + '.txt')

    if port in ['443' , '943']:
        os.system('feroxbuster -u https://' + args.target + ':' + port + ' -t 50 -k -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -e -r -v -n -o webfuzz-' + port + '.txt')

    
    # Nikto
    if port in ['80' , '3080' , '4080' , '5080' , '5357' , '5985' , '6080' , '7080' , '8080' , '13080']:
        os.system('nikto -h http://' + args.target + ':' + port + ' -o nikto-' + port + '.txt')
    if port in ['443' , '943']:
        os.system('nikto -h https://' + args.target + ':' + port + ' -o nikto-' + port + '.txt')


    # RPCBind/PortMapper
    if port in ['111']:
        os.system('rpcinfo ' + args.target + ' > rpcinfo.txt')
        os.system('rpcinfo -s ' + args.target + ' > rpcinfo-concise.txt')
        os.system('nmap -sSUC -p111 -vv -oN rpcbind.nmap ' + args.target)

    # NFS
    if port in ['2049']:
        os.system('nmap -p2049 -Pn -vvv -oN nfs.nmap --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse ' + args.target)


    # MySQL
    if port in ['3306']:
        os.system('nmap -sV -p 3306 --script="mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122" -v -Pn -oN mysql-nmap.txt ' + args.target)

    # Java-RMI
    if port in ['10990' , '37948' , '7099' , '46853' , '6099' , '44941']:
        os.system('java -jar /opt/rmg.jar enum ' + args.target + ' ' + port + ' > rmi-enum-' + port + '.txt')
        os.system('java -jar /opt/rmg.jar guess ' + args.target + ' ' + port + ' > rmi-guess-' + port + '.txt')

    # Apache JServ Protocol 
    if port in ['8008' , '8009']:

        os.system('nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p ' + port + ' -Pn -vv -oN ajp-' + port + '.nmap '+ args.target)

    # RDP
    if port in ['3389']:
        os.system('nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 -vv -Pn -oN rdp.nmap ' + args.target)

    # msrpc
    if port in ['135','49668']:
        os.system('impacket-rpcdump ' + args.target + ' -p ' + port + ' > rpcdump.txt')

    # NetBios
    if port in ['139']:
        os.system('nmblookup -A ' + args.target + ' > nmblookup.txt &&&& nbtscan ' + args.target + '/24 > nbtscan.txt &&&& nmap -sU -sV -T4 --script nbstat.nse -p 137 -Pn -n -oN nbstat.nmap ' + args.target)

    # SMB
    if port in ['445']:
        os.system('python3 /opt/enum4linux-ng/enum4linux-ng.py -A ' + args.target + ' > enum4linux.txt')
        os.system('smbmap -H ' + args.target + ' > smbmap.txt')
        os.system('smbmap -u UserDoesntExist -H ' + args.target + ' > smbmap.txt')
        os.system('smbclient -N -L //' + args.target + ' > smbclient.txt')
        #os.system('rpcclient ' + args.target)
        #os.system('rpcclient -U "" ' + args.target)
        os.system('impacket-getArch -target ' + args.target)
        os.system('nmap -p 139,445 -vv -Pn --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse -oN smb-scan.nmap ' + args.target)

    # IRC
    if port in ['6660']:
        os.system('nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 -Pn -oN irc.nmap ' + args.target)

    # HSQLDB (HyperSQL DataBase) [default creds: sa // blank password]
