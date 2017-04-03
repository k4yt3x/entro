#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
d88888b d8b   db d888888b d8888b.  .d88b.
88'     888o  88 `~~88~~' 88  `8D .8P  88.
88ooooo 88V8o 88    88    88oobY' 88  d'88
88~~~~~ 88 V8o88    88    88`8b   88 d' 88
88.     88  V888    88    88 `88. `88  d8'
Y88888P VP   V8P    YP    88   YD  `Y88P'


Name: ENTR0 Active Defence System
Author: K4T
Date: 4/3/17

Version: 0.9 pre-alpha

Description: An active defense system completed by changing
ssh port every 10 seconds in a range of 1000~9999. The port
number is generated from a random hash. It then publishes the
hash onto the website and the client can then fetch & decode
the port number and connect

TODO:
1. Complete Tor connections for urllib

"""

from __future__ import print_function
import urllib.request
import socket
import os
import re
import base64
import argparse
import time
import hashlib
import configparser
import avalon_framework as avalon

# Unix Console colors
W = '\033[0m'  # white (normal / reset)
R = '\033[31m'  # red
G = '\033[32m'  # green
OR = '\033[33m'  # orange
Y = '\033[93m'  # yellow
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[96m'  # cyan
GR = '\033[37m'  # grey
H = '\033[8m'  # hidden
BD = '\033[1m'  # Bold
NH = '\033[28m'  # not hidden

HOME = os.getenv("HOME")
CONFPATH = HOME + '/.config/entro.conf'


# -------------------------------- Functions Defining --------------------------------

def validIP(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True


def validDomain(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def process_arguments():
	"""
		This funtion takes care of all arguments
	"""
	global args
	parser = argparse.ArgumentParser()
	action_group = parser.add_argument_group('ACTIONS')
	action_group.add_argument("--sftp", help="Connect SFTP", action="store_true", default=False)
	action_group.add_argument("-d", "--debug", help="Debug port connection and decryption; decrypt port but don't connect", action="store_true", default=False)
	action_group.add_argument("-u", "--username", help="-u, --username [username]: Choose which user to connect as", action="store", default="root")
	action_group.add_argument("-s", "--server", help="Connect to a specific server", action="store", default=False)
	action_group.add_argument("-p", "--port", help="Force connecting to a specific port", action="store", default=False)
	action_group.add_argument("-l", "--list", help="Show a list of servers", action="store_true", default=False)
	action_group.add_argument("--tor", help="Connect Using tor", action="store_true", default=False)
	args = parser.parse_args()


def calc_port(hashed):
	ct = 0
	rand_port = ''
	for elmt in hashed:
		if ct < 2:
			if elmt.isdigit():
				rand_port += elmt
				ct += 1
		else:
			break
	return rand_port


def meha(prehash):
	hash1 = hashlib.md5(prehash.encode("UTF-8")).hexdigest()
	hash2 = hashlib.sha256(hash1.encode("UTF-8")).hexdigest()
	hash3 = hashlib.sha384(hash2.encode("UTF-8")).hexdigest()
	hash4 = hashlib.sha512(hash3.encode("UTF-8")).hexdigest()
	hash5 = hashlib.sha384(hash4.encode("UTF-8")).hexdigest()
	hash6 = hashlib.sha256(hash5.encode("UTF-8")).hexdigest()
	hash7 = hashlib.md5(hash6.encode("UTF-8")).hexdigest()
	return hash7


def get_hash():
	if args.debug:
		internet = internet_connected()
		if internet:
			with urllib.request.urlopen('http://' + serverIP + '/entro.hash') as response:
				hash = response.read().decode().split('\n')[0]
				avalon.debug(hash)
				return hash
		else:
			print(avalon.FG.R + avalon.FM.BD + 'INTERNET UNAVAILABLE' + avalon.FM.RST)
			avalon.error('Aborting...')
			exit(1)
	elif args.tor:
		internet = internet_connected()
		print(Y + '[+] INFO: ' + W + 'Getting Hash From Server.......', end='')
		if internet:
			with urllib.request.urlopen('http://' + serverIP + '/entro.hash') as response:
				hash = response.read().decode().split('\n')[0]
				print(avalon.FG.G + avalon.FM.BD + 'OK!' + avalon.FM.RST)
				print(G + '[+] INFO: Got Hash: ' + str(hash) + W)
				return hash
		else:
			print(avalon.FG.R + avalon.FM.BD + 'INTERNET UNAVAILABLE' + avalon.FM.RST)
			avalon.error('Aborting...')
			exit(1)
	else:
		avalon.info('Trying to connect to ' + avalon.FM.BD + serverIP + avalon.FM.RST)
		internet = internet_connected()
		print(Y + '[+] INFO: ' + W + 'Getting Hash From Server using socket.......', end='')
		if internet:
			try:
				sock0 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock0.connect((serverIP, 12021))
				hash = sock0.recv(1024).decode()
				sock0.close()
				print(avalon.FG.G + avalon.FM.BD + 'OK!' + avalon.FM.RST)
				print(G + '[+] INFO: Got Hash: ' + str(hash) + W)
				return hash
			except Exception as er:
				try:
					print(avalon.FG.R + avalon.FM.BD + 'ERROR' + avalon.FM.RST)
					avalon.error('Socket failed: ' + str(er))
					avalon.warning('Trying HTTP...')
					print(Y + '[+] INFO: ' + W + 'Getting Hash From Server..........', end='')
					with urllib.request.urlopen('http://' + serverIP + '/entro.hash') as response:
						hash = response.read().decode().split('\n')[0]
						print(avalon.FG.G + avalon.FM.BD + 'OK!' + avalon.FM.RST)
						print(G + '[+] INFO: Got Hash: ' + str(hash) + W)
						return hash
				except IndexError:
					print(avalon.FG.R + avalon.FM.BD + 'ERROR' + avalon.FM.RST)
					avalon.error('Unable to communicate with server!')
					avalon.error('Is Entr0 server running?')
					exit(0)
		else:
			print(avalon.FG.R + avalon.FM.BD + 'INTERNET UNAVAILABLE' + avalon.FM.RST)
			avalon.error('Aborting...')
			exit(1)


def get_port(hash):
	"""
		Gets the port using hash
		Processes the hash in a certain pattern so the same port would be generated
	"""
	port = ''
	for elmt in hash:
		if elmt == '0' or elmt.isalpha():
			pass
		else:
			port += elmt
			pcc = int(port)
			while True:
				if hash[pcc].isdigit():
					port += hash[pcc]
					break
				else:
					pcc += 1
			return port


def internet_connected():
	"""
	This fucntion detects if the internet is available
	Returns a Boolean value
	"""
	print(avalon.FG.Y + '[+] INFO: ' + avalon.FG.W + 'Checking Internet to Google.................' + avalon.FG.W, end='')
	try:
		socket.create_connection(('www.google.ca', 443), 5)  # Test connection by connecting to google
		print(avalon.FG.G + avalon.FM.BD + 'OK!' + avalon.FM.RST)
		return True
	except socket.error:
		print(avalon.FG.R + 'Google No Respond' + avalon.FG.W)
		try:
			print(avalon.FG.Y + '[+] INFO: ' + avalon.FG.W + 'Checking Internet to DNS....................' + avalon.FG.W, end='')
			socket.create_connection(('8.8.8.8', 53), 5)  # Test connection by connecting to google
			print(avalon.FG.G + avalon.FM.BD + 'OK!' + avalon.FM.RST)
			return True
		except socket.error:
			print(avalon.FG.R + 'Server Timed Out!' + avalon.FG.W)
			return False


def refresh(delay):
	"""
		Pause the program for [delay] seconds
	"""
	for x in range(delay, 0, -1):
		print(P + BD + '\r[#] ENTR0: Next Refresh in ' + C + str(x) + P + ' Seconds ' + W, end='')
		time.sleep(1)
	print('\r                                  \r', end='')


def selectServer():
	"""
		List all servers and let the use choose
	"""
	id = 0
	serversNumerical = []
	print(avalon.FM.BD + '\n[SERVERS]\n' + avalon.FM.RST)
	for server in servers:
		serversNumerical.append(servers[server])
	for server in servers:
		print(avalon.FG.Y + str(id) + ': ' + avalon.FM.RST + servers[server])
		id += 1
	print('')
	while True:
		serverid = avalon.gets('Select Server #: ')
		try:
			return serversNumerical[int(serverid)]
			break
		except IndexError:
			avalon.error('Selected Server not found!')


def setupWizard():
	"""
		Initialize a configuration file in "$HOME/.config/entro.conf"
		Saves all server Names, ID and addresses
	"""
	avalon.info('Set-up Wizard Started')
	config = configparser.ConfigParser()
	config['SERVERS'] = {}
	while True:
		while True:
			serverName = avalon.gets('Server Name: ')
			if serverName == '':
					avalon.error('Invalid Input!')
			else:
				break
		while True:
			serverAddr = avalon.gets('Server Address: ')
			if validIP(serverAddr) or validDomain(serverAddr):
				break
			else:
				avalon.error('Invalid Input! IP addresses or domains only!')
		config['SERVERS'][serverName] = serverAddr
		if avalon.ask('Add another server?'):
			pass
		else:
			break
	avalon.info('Set-up Completed!')
	avalon.info('Writing configuration file to ' + CONFPATH)
	with open(CONFPATH, 'w') as configfile:
		config.write(configfile)  # Writes configurations
	avalon.info('Writing success!')
	avalon.info('Please relaunch application')
	exit(0)


def parseConfig():
	"""
		Reads all configuration files
	"""
	if not os.path.isfile(CONFPATH):
		avalon.warning('Config File Not Found!')
		if avalon.ask('Start Set-up Wizard?', True):
			setupWizard()
		else:
			avalon.error('No configuration file found!')
			avalon.error('Please initialize the config file!')
			exit(0)
	else:
		config = configparser.ConfigParser()
		config.read(CONFPATH)
		config.sections()
		servers = config['SERVERS']
		return servers


# -------------------------------- Procedural Code --------------------------------
try:
	process_arguments()

	servers = parseConfig()
	serverIP = selectServer()

	hash = get_hash()
	hash = base64.b64decode(hash.encode('utf-8')).decode('utf-8')

	if args.port:
		port = args.port
	else:
		port = get_port(hash) + get_port(meha(hash))

	if args.debug:
		avalon.info(R + BD + 'Debug Mode Enabled')
		avalon.info(R + BD + 'Continuely Printing Server info')
		while True:
			hash = get_hash()
			hash = base64.b64decode(hash.encode('utf-8')).decode('utf-8')
			avalon.debug('Port Number Decrypted: ' + Y + BD + str(port))
			refresh(5)
	elif args.sftp and args.tor:
		avalon.info(BD + 'Connecting Using SFTP')
		avalon.info(BD + 'Connecting using Tor')
		os.system('proxychains sftp -P ' + port + ' -o StrictHostKeyChecking=no root@' + serverIP + '')
	elif args.sftp:
		avalon.info(BD + 'Connecting Using SFTP')
		os.system('sftp -P ' + port + ' -o StrictHostKeyChecking=no root@' + serverIP + '')
	elif args.tor:
		avalon.info('Port Number Decrypted: ' + BD + OR + port)
		avalon.info(BD + 'Connecting to SSH')
		avalon.info(BD + 'Connecting using Tor')
		os.system('proxychains ssh -p ' + port + ' ' + args.username + '@' + serverIP + ' -o StrictHostKeyChecking=no')
	else:
		avalon.info('Port Number Decrypted: ' + BD + OR + port)
		avalon.info(BD + 'Connecting to SSH')
		os.system('ssh -p ' + port + ' ' + args.username + '@' + serverIP + ' -o StrictHostKeyChecking=no')
except KeyboardInterrupt:
	print('\n')
	avalon.warning('^C Pressed, Aborting...\n')
	exit(0)
except Exception as er:
	avalon.error(str(er))
	exit(0)
