#!/usr/bin/python

import sys
import os
import optparse
import re
import subprocess
from subprocess import *
import socket
from socket import *
import multiprocessing
from multiprocessing import Process, Queue


def nmapScan(ip_address):
	ip_address = ip_address.strip()
	print "================================================================="
	print "INFO: Running general TCP/UDP nmap port scans for " + ip_address
	print "================================================================="

	portfolder = '/root/pentest/enumeration/'+ip_address+'/ports'
	if not os.path.exists(portfolder):
		print "================================================================="
		print "  Creating: /root/pentest/enumeration/"+ip_address+"/ports"
		print "================================================================="	
    		os.makedirs(portfolder)

   	# NSE Scripts
	#TCPSCAN = "nmap -Pn -sC -sS -T 4 -pT:1-65535 -oA '/root/pentest/enumeration/%s/ports/tcp' %s" % (ip_address, ip_address)
	#UDPSCAN = "nmap -Pn -sC -sS -T 4 -pU:1-65535 -oA '/root/pentest/enumeration/%s/ports/udp' %s" % (ip_address, ip_address)

	# All Ports	
	#TCPSCAN = "nmap -Pn -sS -T 4 -pT:1-65535 -oA '/root/pentest/enumeration/%s/ports/tcp' %s" % (ip_address, ip_address)
	#UDPSCAN = "nmap -Pn -sS -T 4 -pU:1-65535 -oA '/root/pentest/enumeration/%s/ports/udp' %s" % (ip_address, ip_address)
	
	

	TCPSCAN = "nmap -Pn -sS -T 4 -p T:1-8080 -oA '/root/pentest/enumeration/%s/ports/tcp' %s" % (ip_address, ip_address)
	UDPSCAN = "nmap -Pn -sU -T 4 -p U:1-400 -oA '/root/pentest/enumeration/%s/ports/udp' %s" % (ip_address, ip_address)
		
	results_tcp = subprocess.check_output(TCPSCAN, shell=True)
	results_udp = subprocess.check_output(UDPSCAN, shell=True)
	
	with open(os.path.join(portfolder, "combined.ports"), 'a+') as output_file:

		with open("/root/pentest/enumeration/"+ip_address+"/ports/tcp.nmap") as tcp_file:
		    	for line in tcp_file:
				line = line.strip()
				if ("/" in line) and not ("Nmap" in line):
					output_file.write(line+"\n")
		tcp_file.close()

		with open("/root/pentest/enumeration/"+ip_address+"/ports/udp.nmap") as udp_file:
		    	for line in udp_file:
				line.strip()
				if ("/" in line) and not ("Nmap" in line):
					output_file.write(line+"\n")
		udp_file.close()

	output_file.close()

	with open(os.path.join(portfolder, "combined.ports"), 'r') as output_file:
	
		ports = []
		for line in output_file:
			if ("open" in line):
				port = line.split(" ")[0]
				ports.append(port)

	print "======================================="
	print "all ports in ports array for debugging"
	print ports
	print "======================================="


	for port in ports: 
		if (port == "21/tcp"):
			print "FTP"

			ftp_folder = '/root/pentest/enumeration/'+ip_address+'/ftp'
			if not os.path.exists(ftp_folder):
				print "================================================================="
				print "  Creating: /root/pentest/enumeration/"+ip_address+"/ftp"
				print "================================================================="	
		    		os.makedirs(ftp_folder)

			nmap_scripts = "ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221"
			nmap_output = "/root/pentest/enumeration/"+ip_address+"/ftp/"
			scan = "nmap -sV -Pn -vv -p 21 --script="+nmap_scripts+" -oN '"+nmap_output+"nmap' %s" % (ip_address)
			results = subprocess.check_output(scan, shell=True)
			

			hydra_users = "/usr/share/wordlists/usernames.txt"
			hydra_passwords = "/usr/share/wordlists/rockyou.txt"
			hydra_results = ftp_folder+"/ftphydra.txt"
			hydra_ftp = "hydra -L "+hydra_users+" -P "+hydra_passwords+" -f -o "+hydra_results+" -u %s -s 21 ftp" % (ip_address)
			results = subprocess.check_output(hydra, shell=True)


		elif (port == "22/tcp"):
			print "SSH"
			ssh_folder = '/root/pentest/enumeration/'+ip_address+'/ssh'
			if not os.path.exists(ssh_folder):
				print "================================================================="
				print "  Creating: /root/pentest/enumeration/"+ip_address+"/ssh"
				print "================================================================="	
		    		os.makedirs(ssh_folder)
			
			ssh_output = "/root/pentest/enumeration/"+ip_address+"/ssh/nmap"
			ssh_nmap = "nmap -Pn -sU -p22 --script='ssh-hostkey,ssh2-enum-algos' -oA '"+ssh_output+"' %s" % (ip_address)
			result = subprocess.check_output(ssh_nmap, shell=True)


			hydra_users = "/usr/share/wordlists/usernames.txt"
			hydra_passwords = "/usr/share/wordlists/rockyou.txt"
			hydra_results = ssh_folder+"/sshhydra.txt"
			hydra_ssh = "hydra -L "+hydra_users+" -P "+hydra_passwords+" -f -o "+hydra_results+" -u %s -s 22 ssh" % (ip_address)
			results = subprocess.check_output(hydra, shell=True)


		elif (port == "23/tcp"):
			print "TELNET"


		elif (port == "25/tcp"):
			print "SMTP"
			smtp_folder = '/root/pentest/enumeration/'+ip_address+'/smtp'
			if not os.path.exists(smtp_folder):
				print "================================================================="
				print "  Creating: /root/pentest/enumeration/"+ip_address+"/smtp"
				print "================================================================="	
		    		os.makedirs(smtp_folder)

			s = (	"smtp-brute,smtp-commands,smtp-enum-users,smtp-ntlm-info,"
				"smtp-open-relay,smtp-strangeport,smtp-vuln-cve2010-4344,"
				"smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764")

			smtp_path = "/root/pentest/enumeration/"+ip_address+"/smtp/nmap"
			smtp_nmap = "nmap -T4 -p 25 --script='"+s+"' -oA '"+smtp_path+"' %s" % (ip_address)
			result = subprocess.check_output(smtp_nmap, shell=True)


			#/usr/share/golismero/wordlist/fuzzdb/Discovery/PredictableRes/tftp.fuzz.txt

			names = open('cat /usr/share/nmap/nselib/data/usernames.lst', 'r')
			for name in names:
				s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				connect=s.connect((ip_address,25))
				banner=s.recv(1024)
				s.send('HELO '+name.strip()+'@thinc.local \r\n')
				result = s.recv(1024)
				s.send('VRFY ' + name.strip() + '\r\n')
				result =s.recv(1024)
				if ("not implemented" in result) or ("disallowed" in result):
					sys.exit("INFO: VRFY Command not implemented on " + sys.argv[1]) 
				if (("250" in result) or ("252" in result) and ("Cannot VRFY" not in result)):
					print "[*] SMTP VRFY Account found on " + sys.argv[1] + ": " + name.strip()	
				s.close()



		elif (port == "53/tcp"):
			print "DNS"


		elif (port == "69/udp"):
			print "TFTP"
			tftp_folder = '/root/pentest/enumeration/'+ip_address+'/tftp'
			if not os.path.exists(tftp_folder):
				print "================================================================="
				print "  Creating: /root/pentest/enumeration/"+ip_address+"/tftp"
				print "================================================================="	
		    		os.makedirs(tftp_folder)
			#/usr/share/golismero/wordlist/fuzzdb/Discovery/PredictableRes/tftp.fuzz.txt
			tftp_nmap = "nmap -Pn -sU -p69 --script=tftp-enum -oA '/root/pentest/enumeration/%s/tftp/' %s" % (ip_address, ip_address)
			result = subprocess.check_output(tftp_nmap, shell=True)


		elif (port == "80/tcp"):
			print "HTTP"	
			http_folder = '/root/pentest/enumeration/'+ip_address+'/http'
			if not os.path.exists(http_folder):
				print "================================================================="
				print "  Creating: /root/pentest/enumeration/"+ip_address+"/http"
				print "================================================================="	
		    		os.makedirs(http_folder)

			s = (	"http-affiliate-id,http-apache-negotiation,http-apache-server-status,http-aspnet-debug,"
				"http-auth-finder,http-backup-finder,http-cakephp-version,http-chrono,http-cisco-anyconnect,"
				"http-comments-displayer,http-cors,http-date,http-default-accounts,http-devframework,http-drupal-enum,"
				"http-drupal-enum-users,http-enum,http-errors,http-favicon,http-feed,http-generator,"
				"http-gitweb-projects-enum,http-google-malware,http-grep,http-headers,http-icloud-findmyiphone,"
				"http-icloud-sendmsg,http-internal-ip-disclosure,http-ls,http-mcmp,http-mobileversion-checker,http-ntlm-info,"
				"http-open-proxy,http-open-redirect,http-php-version,http-qnap-nas-info,http-referer-checker,http-robots.txt,"
				"http-robtex-reverse-ip,http-robtex-shared-ns,http-sitemap-generator,http-svn-enum,http-svn-info,http-title,"
				"http-trace,http-traceroute,http-unsafe-output-escaping,http-useragent-tester,http-vhosts,"
				"http-vlcstreamer-ls,http-waf-detect,http-waf-fingerprint,http-webdav-scan,http-wordpress-enum,http-xssed")

			http_path = "/root/pentest/enumeration/"+ip_address+"/http/nmap"
			http_nmap = "nmap -T4 -p80,443 --script='"+s+"' -oA '"+http_path+"' %s" % (ip_address, ip_address)
			result = subprocess.check_output(http_nmap, shell=True)

			folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns"]

			found = []
			print "INFO: Starting dirb scan for " + url
			for folder in folders:
			    for filename in os.listdir(folder):

				http_path = " -o /root/pentest/enumeration/"+ip_address+"/http/dirb/"+filename
				dirb_scan = "dirb %s %s/%s %s -S -r" % (ip_address, folder, filename, http_path)
				try:
				    results = subprocess.check_output(dirb_scan, shell=True)
				    resultarr = results.split("\n")
				    for line in resultarr:
					if "+" in line:
					    if line not in found:
						found.append(line)
				except:
				    pass
			
			print "=================== FOUND VAR IN DIRB ============================="
			print found
			print "==================================================================="

		elif (port == "88/tcp"):
			print "Kerberos"


		elif (port == "111/udp"):
			print "Linux RPC"


		elif (port == "123/udp"):
			print "NTP"
			ntp_folder = '/root/pentest/enumeration/'+ip_address+'/ntp'
			if not os.path.exists(ftp_folder):
				print "================================================================="
				print "  Creating: /root/pentest/enumeration/"+ip_address+"/ntp"
				print "================================================================="	
		    		os.makedirs(ftp_folder)

			nmap_scripts = "ntp-info,ntp-monlist"
			nmap_output = "/root/pentest/enumeration/"+ip_address+"/ntp/"
			scan = "nmap -sU -sV -Pn -vv -p 123 --script="+nmap_scripts+" -oN '"+nmap_output+"nmap' %s" % (ip_address)
			results = subprocess.check_output(scan, shell=True)


		elif (port == "135/tcp"):
			print "MS RPC Mapper"


		elif (port == "139/tcp"):
			print "NetBios"
			netbios_folder = '/root/pentest/enumeration/'+ip_address+'/netbios'
			if not os.path.exists(netbios_folder):
				print "================================================================="
				print "  Creating: /root/pentest/enumeration/"+ip_address+"/tftp"
				print "================================================================="	
		    		os.makedirs(netbios_folder)
			
			nbt_cmd = "nbtscan -O "+netbios_folder+"/nbtscan %s" % (ip_address)
			result = subprocess.check_output(nbt_cmd, shell=True)

			nmb_cmd = "nmblookup -A %s > "+netbios_folder+"/nmblookup " % (ip_address)
			result = subprocess.check_output(nmb_cmd, shell=True)


		elif (port == "161/tcp"):
			print "SNMP"
			snmp_path = '/root/pentest/enumeration/'+ip_address+'/snmp'
			if not os.path.exists(snmp_path):
				print "================================================================="
				print "  Creating: /root/pentest/enumeration/"+ip_address+"/snmp"
				print "================================================================="	
		    		os.makedirs(snmp_path)
			
			swalk = "snmpwalk -v 1 -c public %s > /root/pentest/enumeration/%s/snmp/snmpwalk" % (ip_address, ip_address)
			results = subprocess.check_output(swalk, shell=True)

			onesixtyone = "onesixtyone %s" % (ip_address)
			results = subprocess.check_output(onesixtyone, shell=True)
			
			nmap_path = "/root/pentest/enumeration/"+ip_address+"/snmp/nmap"
			nmap_scan = "nmap -vv -sV -sU -Pn -p 161,162 -oA "+nmap_path+" --script=snmp-netstat,snmp-processes %s" % (ip_address)
			results = subprocess.check_output(nmap_scan, shell=True)
				
			#snmp-check -t 192.168.1.2 -c public


		elif (port == "389/tcp"):
			print "LDAP"

		elif (port == "389/udp"):
			print "Kerberos"	

		elif (port == "443/tcp"):
			print "HTTPS"	
			http_folder = '/root/pentest/enumeration/'+ip_address+'/http'
			if os.path.exists(https_folder):
				continue

			print "================================================================="
			print "  Creating: /root/pentest/enumeration/"+ip_address+"/http"
			print "================================================================="	
	    		os.makedirs(http_folder)

			s = (	"http-affiliate-id,http-apache-negotiation,http-apache-server-status,http-aspnet-debug,"
				"http-auth-finder,http-backup-finder,http-cakephp-version,http-chrono,http-cisco-anyconnect,"
				"http-comments-displayer,http-cors,http-date,http-default-accounts,http-devframework,http-drupal-enum,"
				"http-drupal-enum-users,http-enum,http-errors,http-favicon,http-feed,http-generator,"
				"http-gitweb-projects-enum,http-google-malware,http-grep,http-headers,http-icloud-findmyiphone,"
				"http-icloud-sendmsg,http-internal-ip-disclosure,http-ls,http-mcmp,http-mobileversion-checker,http-ntlm-info,"
				"http-open-proxy,http-open-redirect,http-php-version,http-qnap-nas-info,http-referer-checker,http-robots.txt,"
				"http-robtex-reverse-ip,http-robtex-shared-ns,http-sitemap-generator,http-svn-enum,http-svn-info,http-title,"
				"http-trace,http-traceroute,http-unsafe-output-escaping,http-useragent-tester,http-vhosts,"
				"http-vlcstreamer-ls,http-waf-detect,http-waf-fingerprint,http-webdav-scan,http-wordpress-enum,http-xssed")
			
			http_path = "/root/pentest/enumeration/"+ip_address+"/http/nmap"
			http_nmap = "nmap -T4 -p80,443 --script='"+s+"' -oA '"+http_path+"' %s" % (ip_address, ip_address)
			result = subprocess.check_output(http_nmap, shell=True)

		elif (port == "445/tcp"):
			print "SMB"
			smb_path = '/root/pentest/enumeration/'+ip_address+'/smb'
			if not os.path.exists(smb_path):
				print "================================================================="
				print "  Creating: /root/pentest/enumeration/"+ip_address+"/smb"
				print "================================================================="	
		    		os.makedirs(smb_path)

			output = "/root/pentest/enumeration/"+ip_address+"/smb/samrdump.txt"
			samrdump = "python /usr/share/doc/python-impacket/examples/samrdump.py %s > "+output % (ip_address)
			results = subprocess.check_output(swalk, shell=True)


		elif (port == "446/tcp"):
			print "Kerberos Kpasswd: Related Ports 88,543,544,749"

		elif (port == "593/tcp"):
			print "http-rpc-epmap"

		elif (port == "636/tcp"):
			print "ldapssl"

		elif (port == "3268/tcp"):
			print "globalcatLDAP"
		
		elif (port == "3269/tcp"):
			print "globalcatLDAPssl"
 
		elif (port == "3389/tcp"):
			print "Windows RDP"

def main():
	print "Main Function Call"
	
if __name__ == '__main__':
	print "Machine Enumerator By EvilSaint"
	parser = optparse.OptionParser("usage: ./enumerate.py "+"-i <ip_address> -f <host_list>")
	parser.add_option('-i', dest='ip_address', type='string', help='IP Address')
	parser.add_option('-f', dest='host_list', type='string', help='Host List File')
	(options, args) = parser.parse_args()

	if (options.ip_address == None) and (options.host_list == None):
		print parser.usage
		exit(0)
	else:
		ip_address = options.ip_address
		host_list = options.host_list

	scanfolder = '/root/pentest/enumeration/'+ip_address
	if not os.path.exists(scanfolder):
		print "===================================================="
		print "  Creating: /root/pentest/enumeration/"+ip_address
		print "===================================================="
    		os.makedirs(scanfolder)

	jobs = []
	p = multiprocessing.Process(target=nmapScan, args=(ip_address,))
	jobs.append(p)
	p.start()
	main()
