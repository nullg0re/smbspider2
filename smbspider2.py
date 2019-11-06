#!/usr/bin/python
import os
import time
import concurrent.futures
import Queue
import threading
import argparse
import socket
from netaddr import *
from nmb.NetBIOS import NetBIOS
from smb.SMBConnection import SMBConnection
from colorama import Fore, Style

# Global
patterns = ['.ps1','.kdb','.kdbx','password']

class scan_thread(threading.Thread):
	def __init__(self,ip,user,pwd,domain):
		threading.Thread.__init__(self)
		self.ip = ip
		self.user = user
		self.pwd = pwd
		self.domain = domain

	def run(self):
		if self.ip is None:
			print(Fore.YELLOW+Style.DIM+"[*] No IP to go after, moving to next target..."+Style.RESET_ALL)
		else:
			print(Fore.YELLOW+"[+] Starting thread for " + self.ip+Style.RESET_ALL)
			net = NetBIOS()
			net_name = str(net.queryIPForName(self.ip)).strip("['").strip("']")
			net.close()
			conn = SMBConnection(self.user, self.pwd, 'cobwebs', net_name, domain=self.domain, use_ntlm_v2 = True, is_direct_tcp=True)
			if conn.connect(self.ip, port=445, timeout=10):
				print(Fore.GREEN+"[+] Connection to %s Successful! Time to Spider!" % self.ip+Style.RESET_ALL)
			else:
				print(Fore.RED+"[!] Connection Failed to %s!" % self.ip+Style.RESET_ALL)

			shares = conn.listShares()
			for share in shares:
				if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
					x = True
					while x == True:
						x = recurse(conn,self.ip,share,"/")
						if x == False:
							break
			conn.close()

def scan(ip):
	print(Fore.YELLOW+"[*] Scanning Port 445 on host " + ip+Style.RESET_ALL)
	try:
		sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.settimeout(3)
		result = sock.connect_ex((ip,445))
		if result == 0:
			print(Fore.GREEN+"[+] Viable Host: %s" % ip +Style.RESET_ALL)
			return ip
		else:
			return "0.0.0.0"
		sock.close()
	except Exception as e:
		print(Fore.RED+"[!] Connection to %s failed!" % ip +Style.RESET_ALL)

def recurse(smb_conn,ip,share,subfolder):
	try:
		filelist = smb_conn.listPath(share.name, subfolder)
		dir_list(smb_conn, filelist, ip, subfolder,share.name)
	except:
#		print("//%s/%s/%s [Unable to read]" % (ip,share.name, subfolder.replace("//","")))
		return False
	for result in filelist:
		if result.isDirectory and result.filename != '.' and result.filename != '..':
			recurse(smb_conn,ip,share,result.filename)
	return False

def dir_list(smb_conn,files,ip,path,share):
	for result in files:
		for pattern in patterns:
			if pattern in result.filename:
				print(Fore.GREEN+Style.BRIGHT+"[+] //%s/%s/%s/%s" % (ip,share,path.replace("//",""),result.filename)+Style.RESET_ALL)
				print(Fore.YELLOW+"[+] Downloading Found File..."+Style.RESET_ALL)
				pull_file(smb_conn,result.filename,ip,path,share)


def pull_file(smb_conn,file,ip,path,share):
	filename = ip+"/"+share+"/"+file
	if not os.path.exists(os.path.dirname(filename)):
		try:
			os.makedirs(os.path.dirname(filename))
		except OSError as exc:
			if exc.errno != errno.EEXIST:
				raise
	with open(filename, 'wb') as f:
		try:
			file_attributes, filesize = smb_conn.retrieveFile(share,path+'\\'+file,f)
		except Exception as e:
			print(str(e))

def get_ips(iparg):
	ips = []
	try:
		if os.path.isfile(iparg):
			f = open(iparg,'r')
			for line in f:
				line = line.rstrip()
				if '/' in line:
					for ip in IPNetwork(line).iter_hosts():
						ips.append(str(ip))
				else:
					ips.append(line)
			f.close()
			return ips
		if '/' in iparg:
			for ip in IPNetwork(iparg).iter_hosts():
				ips.append(str(ip))
		else:
			ips.append(str(IPAddress(iparg)))
	except:
		print ("Error reading file or IP Address notation: %s" % iparg)
		exit()
	return ips

def main():
	parser = argparse.ArgumentParser(description="SMB Spider for PS1 Scripts")
	parser.add_argument('-ip','--ipaddress',help='ip address',required=True)
	parser.add_argument('-u','--user',help='user',required=True)
	parser.add_argument('-p','--pwd',help='password',required=True)
	parser.add_argument('-d','--domain',help='domain',required=True)
	parser.add_argument('-t','--threads',help='number of threads',default=1, required=False)
	args = parser.parse_args()

	# Get the list of ips
	ips = get_ips(args.ipaddress)

	start_time = time.time()

	raw_hosts = []
	valid_hosts = []

	with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
		future_to_ip = {executor.submit(scan, ip): ip for ip in ips}
		for future in concurrent.futures.as_completed(future_to_ip):
			ip = future_to_ip[future]
			try:
				raw_hosts.append(future.result())
			except Exception as exc:
				print(Fore.RED+"[!] ERROR %s" % exc + Style.RESET_ALL)

	for host in raw_hosts:
		if host == "0.0.0.0":
			continue
		else:
			valid_hosts.append(host)

	for ip in valid_hosts:
		thread = scan_thread(ip,args.user,args.pwd,args.domain)
		thread.start()

		while threading.activeCount() > int(len(valid_hosts)):
			time.sleep(0.01)

	#make sure all spidering threads are dead before closing primary thread
	while threading.activeCount() > 1:
		time.sleep(0.01)

	print (Fore.GREEN+"[+] Done spidering...\r\nCompleted in: %s" % (time.time() - start_time)+Style.RESET_ALL)

if __name__ == '__main__':
	main()
