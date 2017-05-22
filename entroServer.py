#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
d88888b d8b   db d888888b d8888b.  .d88b.      .d8888. db    db d8888b.
88'     888o  88 `~~88~~' 88  `8D .8P  88.     88'  YP 88    88 88  `8D
88ooooo 88V8o 88    88    88oobY' 88  d'88     `8bo.   Y8    8P 88oobY'
88~~~~~ 88 V8o88    88    88`8b   88 d' 88       `Y8b. `8b  d8' 88`8b
88.     88  V888    88    88 `88. `88  d8'     db   8D  `8bd8'  88 `88.
Y88888P VP   V8P    YP    88   YD  `Y88P'      `8888Y'    YP    88   YD


Name: ENTR0 Active Defense System (SERVER SIDE)
Author: K4T
Date: 4/15/17

Version: 1.1 beta

Description: An active defense system completed by changing
ssh port every 10 seconds in a range of 1000~9999. The port
number is generated from a random hash. It then publishes the
hash onto the website and the client can then fetch & decode
the port number and connect

Known Bugs:
	Unable to close socket server correctly. Server waits for around 30
		seconds until the operating system recycles the port. Will be fixed
		before beta.

"""

import hashlib
import random
import string
import time
import os
import shutil
import psutil
import base64
import multiprocessing
import socket
import avalon_framework as avalon

# Console colors
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
BD = '\033[1m'  # BOLD
NH = '\033[28m'  # not hidden

SSHD_CONFIG = '/etc/ssh/sshd_config'
TEMP = '/tmp/sshd_config'
PUB = '/usr/share/wordpress/entro.hash'


def port_not_used(lport):
	"""
	Test if port is already being used by other programs
	"""
	lport = str(lport)
	for connection in psutil.net_connections():
		host, port = connection.laddr
		if host == '0.0.0.0' and str(port) == lport:
			return False
	return True


def meha(prehash, seed):
	"""
	Multi-Encryption Hashing Algorithm with seed
	The seed decides the order of encrypting
	Different seed will result in a completely
	different output

	The server must have the EXACT same seed as
	the client for them to connect successfully

	Seed Map:
	1: MD5
	2: SHA256
	3: SHA384
	4: SHA512
	"""
	finhash = ''
	seed = str(seed)
	for idn in range(len(seed)):
		if seed[idn] == '1':
			if len(finhash) == 0:
				finhash = hashlib.md5(prehash.encode("UTF-8")).hexdigest()
			else:
				finhash = hashlib.md5(finhash.encode("UTF-8")).hexdigest()
		elif seed[idn] == '2':
			if len(finhash) == 0:
				finhash = hashlib.sha256(prehash.encode("UTF-8")).hexdigest()
			else:
				finhash = hashlib.sha256(finhash.encode("UTF-8")).hexdigest()
		elif seed[idn] == '3':
			if len(finhash) == 0:
				finhash = hashlib.sha384(prehash.encode("UTF-8")).hexdigest()
			else:
				finhash = hashlib.sha384(finhash.encode("UTF-8")).hexdigest()
		elif seed[idn] == '4':
			if len(finhash) == 0:
				finhash = hashlib.sha512(prehash.encode("UTF-8")).hexdigest()
			else:
				finhash = hashlib.sha512(finhash.encode("UTF-8")).hexdigest()
	return finhash


def meha_salt(prehash):
	"""
	Gives a high entropy MD5 Hash, which will
	in generating a completely random port
	"""
	salts = [''.join([random.choice(string.printable) for _ in range(40)]) for _ in range(7)]

	hash1 = hashlib.md5((prehash + salts[0]).encode("UTF-8")).hexdigest()
	hash2 = hashlib.sha256((hash1 + salts[1]).encode("UTF-8")).hexdigest()
	hash3 = hashlib.sha384((hash2 + salts[2]).encode("UTF-8")).hexdigest()
	hash4 = hashlib.sha512((hash3 + salts[3]).encode("UTF-8")).hexdigest()
	hash5 = hashlib.sha384((hash4 + salts[4]).encode("UTF-8")).hexdigest()
	hash6 = hashlib.sha256((hash5 + salts[5]).encode("UTF-8")).hexdigest()
	hash7 = hashlib.md5((hash6 + salts[6]).encode("UTF-8")).hexdigest()
	return hash7


def get_port(shash):
	port = ''
	for elmt in shash:
		if elmt == '0' or elmt.isalpha():
			pass
		else:
			port += elmt
			pcc = int(port)
			while True:
				if shash[pcc].isdigit():
					port += shash[pcc]
					break
				else:
					pcc += 1
			return port


def set_port(port):
	with open(TEMP, 'w') as temp:
		with open(SSHD_CONFIG, 'r') as sshd:
			for line in sshd:
				if line[0:5] != 'Port ':
					temp.write(line)
			temp.write('Port ' + str(port) + '\n')
	shutil.move(TEMP, SSHD_CONFIG)
	os.system('service ssh restart')


def sockDaemon():
	while True:
		sock0 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock0.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock0.bind(('0.0.0.0', 12021))
		sock0.listen(1)
		while True:
			try:
				conn, (rip, rport) = sock0.accept()
				conn.send(FHASH.encode('utf-8'))
			except OSError:
				avalon.error('Socket port is being used!')
				sock0.close()
				avalon.info('Fail-Safe: Trying to reassign socket...')
				break
			except Exception as er:
				avalon.error('Socket: ' + str(er))
				sock0.close()
				avalon.info('Fail-Safe: Trying to reload socket daemon...')
			finally:
				conn.close()
				time.sleep(0.5)


def publish_hash():
	if os.path.isfile(PUB):
		os.remove(PUB)
	with open(PUB, 'w') as pub:
		pub.write(FHASH)
	pub.close()


avalon.info('Entr0 Server Initialized!')


while True:
	shash = meha_salt('Entr0 Project')
	port = get_port(shash) + get_port(meha(shash, 1423241))
	FHASH = base64.b64encode(shash.encode('utf-8')).decode('utf-8')
	print(Y + '[+] INFO: Changing to Port: ' + G + str(port) + W)
	set_port(port)
	print(Y + '[+] INFO: Changed!' + W)
	print(Y + '[+] INFO: Publishing Hash: ' + G + str(FHASH) + W)
	try:
		sockd.terminate()
	except NameError:
		pass
	publish_hash()
	sockd = multiprocessing.Process(target=sockDaemon)
	sockd.start()
	print(Y + '[+] INFO: Published!' + W)
	for x in range(10, 0, -1):
		print(P + BD + '\r[#] Entr0: Next Change in ' + C + str(x) + P + ' Seconds ' + W, end='')
		time.sleep(1)
	out = '[#] Entr0: Next Change in ' + str(x) + ' Seconds '
	print('\r' + (len(out) * ' ') + '\r', end='')
