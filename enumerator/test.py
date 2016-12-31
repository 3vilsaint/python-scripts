#!/usr/bin/python

import sys
import os
import optparse
import socket
from socket import *

if len(sys.argv)==2:
	filename = sys.argv[1]
	print "[+] Reading Vulnerabilities From: "+filename

def retBanner(ip, port):
	try:
		socket.setdefaulttimeout(2)
		s = socket.socket()
		s.connect((ip, port))
		banner = s.recv(1024)
		return banner
	except:
		return
def checkVulns(banner):
	if 'FreeFloat Ftp Server (Version 1.00)' in banner:
		print '[+] FreeFloat FTP Server is vulnerable.'
	elif '3Com 3CDaemon FTP Server Version 2.0' in banner:
		print '[+] 3CDaemon FTP Server is vulnerable.'
	elif 'Ability Server 2.34' in banner:
		print '[+] Ability FTP Server is vulnerable.'
	elif 'Sami FTP Server 2.0.2' in banner:
		print '[+] Sami FTP Server is vulnerable.'
	else:
		print '[-] FTP Server is not vulnerable.'
	return
def main():
	parser = optparse.OptionParser("usage%prog "+\
	"-f <zipfile> -d <dictionary>")
	parser.add_option('-f', dest='zname', type='string',\
	help='specify zip file')
	parser.add_option('-d', dest='dname', type='string',\
	help='specify dictionary file')
	(options, args) = parser.parse_args()
	if (options.zname == None) | (options.dname == None):
		print parser.usage
		exit(0)
	else:
		zname = options.zname
		dname = options.dname
	portList = [21,22,25,80,110,443]
	for x in range(1, 255):
		ip = '10.11.1.' + str(x)
		for port in portList:
			banner = retBanner(ip, port)
			if banner:
				print '[+] ' + ip + ': ' + banner
				checkVulns(banner)

if __name__ == '__main__':
	main()
