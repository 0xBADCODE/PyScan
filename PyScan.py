#!/usr/bin/env python
#Proof of concept port scanner by Xeon

import socket
import sys
import os
import subprocess
import random
import argparse
from array import array
from datetime import datetime

p = argparse.ArgumentParser()
p.add_argument('addr', help='Fully Qualified Domain Name | IP Address')
p.add_argument('-v', help='Verbose', action='store_true')
p.add_argument('-F', help='Resolve FQDN from IP', action='store_true')
p.add_argument('-N', help='Do not ping host', action='store_true')
p.add_argument('-r', help='Randomize port sequence', action='store_true')
p.add_argument('-a', help='Scan all 65535 ports', action='store_true')
p.add_argument('-O', help='Ennumerate target', action='store_true')
p.add_argument('-p', help='Specific port', nargs='*', type=int)
args = p.parse_args()

subprocess.call('clear', shell=False) #clear screen

if len(sys.argv) < 2: #check args
	print 'Usage: %s takes an IP or FQDN as argument [options]' % sys.args[0]
	print 'e.g. %s 192.168.0.1 -arF' % sys.argv[0]
	sys.exit(1)

t1 = datetime.now()

if os.getuid() != 0: print 'For full functionality, run as root.'
print 'Scanning host: ', args.addr
print '-' * 30
if args.v: print args

def ping(addr):
	if args.N: #dont ping host
		return True	
	else: #check host is up by ping
		if os.system('/bin/ping -c 1 ' + addr + ' > /dev/null') == 0: 
			return True
		else: 
			print '\nHost appears to be down or not responding to ICMP packets'
			print 'Try -N flag'
			return False
		
def rand_ports():
	portlist = []
	for i in range(1,65536): #all ports
		portlist.append(i)
	random.shuffle(portlist) #randomize ports
	return portlist

def grab_http(remote_port): #grab http headers
	curl = subprocess.Popen(['curl', '-I', remote_host + ':' + str(remote_port)], shell=False, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
	header, error = curl.communicate()
	return header

def grab_ssl(remote_port): #grab ssl protocol info
	ssl = subprocess.Popen(['openssl', 's_client', '-showcerts', '-connect', remote_host + ':' + str(remote_port)], shell=False, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
	ssl_info, error = ssl.communicate()
	return ssl_info

def grab_ssh(remote_port): #grab ssh protocol info
	ssh = subprocess.Popen(['curl', '-I', remote_host + ':' + str(remote_port)], shell=False, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        ssh_info, error = ssh.communicate()
        return ssh_info

def ennumerate(p_open):
	for port in p_open:
		if port in [80,8080]: #grab http headers
			print '\nHTTP header data on port %d:\n%s' % (port, grab_http(port))
		elif port in [443,6697]: #grab ssl certs
			print '\nSSL cert info on port %d:\n%s' % (port, grab_ssl(port))
		elif port in [22]: #grab ssh info
			print '\nSSH protocol info on port %d:\n%s' % (port, grab_ssh(port))
	
try:
	remote_host = socket.gethostbyname(args.addr) #resolve IP
	if args.F: print 'FQDN: ', socket.getfqdn(args.addr)
	 
except socket.gaierror:
    print 'Hostname could not be resolved. Exiting'
    sys.exit(1)

if ping(remote_host):
	if args.a: portlist = rand_ports()
	elif args.p != None: portlist = args.p
	else: portlist = [21,22,23,25,53,80,110,139,443,1337,1723,2222,5222,6667,6697,8080,9001,9030] #common ports to check
	
	if args.v: print 'Portlist -', str(portlist)
	if args.r: random.shuffle(portlist) #randomize ports

	try:
		total = 0
		p_open = []

		for remote_port in portlist:

			if args.v: print 'Checking TCP port %d' % remote_port
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #open tcp socket
			sock.settimeout(1)
			total += 1

			if total % 1000 == 0:
				x = 100.0*(total-len(p_open))/len(portlist) #status update
				print 'Scan at %f percent' % x

			if sock.connect_ex((remote_host, remote_port)) == 0:
				if args.v: print 'Found port %d open' % remote_port
				p_open.append(remote_port)
				sock.close()

		if args.O: ennumerate(sorted(p_open)) #ennumerate target

		if len(p_open) > 0: print '\nPort %s is open' % str(sorted(p_open)) #report open ports
		print '\n%d ports open (%d filtered|closed)' % (len(p_open), total-len(p_open))
		
	except KeyboardInterrupt:

	    if len(p_open) > 0: print '\nPort %s is open' % str(sorted(p_open)) #report open ports
            print '\n%d ports open (%d filtered|closed)' % (len(p_open), total-len(p_open))

	    print 'You pressed Ctrl+C. Exiting'
	    sys.exit(1)
	 
	except socket.error:
	    print 'Could not connect to server'
	    sys.exit(2)

print 'Scan complete: ', datetime.now()-t1 #scan time
sys.exit(0)
