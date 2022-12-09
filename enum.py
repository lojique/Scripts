   #!/bin/python3

import os
import re
import subprocess
import ipaddress
import requests
import glob
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-target', metavar='IP_Addr', type=str, help='IP Address or Domain')
parser.add_argument('-target_list', metavar='hosts.lst', type=str, help='List of IP Addresses and/or Domains')

args = parser.parse_args()

#Create Directory for target and move target list into new directory and cd into directory for rest of script
os.system('mkdir ' + args.target)
#os.system('mv ' + args.target_list + ' ' + args.target)
os.chdir(args.target)
os.system('cp /opt/SSHScan/config.yml .')

os.system('nmap -p22 -oN ssh-nmap.txt -Pn --open --script="banner,ssh-hostkey,ssh-auth-methods" ' + args.target)
os.system('python3 /opt/SSHScan/sshscan.py -t ' + args.target + ' > sshscan.txt')
os.system('ssh-audit --level=warn ' + args.target + ' > ssh-audit.txt')
os.system('ssh-keyscan -t rsa ' + args.target + ' > ssh-keyscan.txt')

# SMTP
os.system('sudo nmap --script=smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-open-relay,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 ' + args.target + ' -Pn -oN smtp-scan -vvv')

os.system('openssl s_client -connect ' + args.target + ':443')

# WhatWeb
os.system('whatweb -a 3 http://' + args.target + ' > whatweb-http.txt')


# SSLScan
os.system('sslscan ' + args.target + ' > sslscan.txt')


# TestSSL
os.system('/opt/testssl.sh-3.0.8/testssl.sh ' + args.target + ' > testssl.txt')

# HTTP Nmap
os.system('nmap -vv -oN http-nmap.txt --open --reason -Pn -sV -p 80,443,943 --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" ' + args.target)

# Web Fuzz
os.system('ffuf -u https://' + args.target + '/FUZZ -r -c -v -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt > webfuzz.txt')
os.system('gobuster dir -u https://' + args.target + ' -k -t 50 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --exclude-length 0 > webfuzz.txt')

# Nikto
os.system('nikto -h https://' + args.target + ' -o nikto.txt')

# RPCBind/PortMapper
os.system('rpcinfo ' + args.target + ' > rpcinfo.txt')
os.system('rpcinfo -s ' + args.target + ' > rpcinfo-concise.txt')
os.system('nmap -sSUC -p111 -vv -oN rpcbind.nmap ' + args.target)

# NFS
os.system('nmap -p2049 -Pn -vvv -oN nfs.nmap --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse ' + args.target)
