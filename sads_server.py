#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""
 .d8888b.         d8888 8888888b.   .d8888b.       .d8888b.  888     888 8888888b.
d88P  Y88b       d88888 888  "Y88b d88P  Y88b     d88P  Y88b 888     888 888   Y88b
Y88b.           d88P888 888    888 Y88b.          Y88b.      888     888 888    888
 "Y888b.       d88P 888 888    888  "Y888b.        "Y888b.   Y88b   d88P 888   d88P
    "Y88b.    d88P  888 888    888     "Y88b.         "Y88b.  Y88b d88P  8888888P"
      "888   d88P   888 888    888       "888           "888   Y88o88P   888 T88b
Y88b  d88P  d8888888888 888  .d88P Y88b  d88P     Y88b  d88P    Y888P    888  T88b
 "Y8888P"  d88P     888 8888888P"   "Y8888P"       "Y8888P"      Y8P     888   T88b


Name: SADS Active Defence System (SERVER SIDE)
Author: K4T
Date: 2/19/17

Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt

(C) 2017 K4YT3X

Description: An active defense system completed by changing
ssh port every 10 seconds in a range of 1000~9999. The port
number is generated from a random hash. It then publishes the
hash onto the website and the client can then fetch & decode
the port number and connect

"""
import hashlib
import random
import string
import time
import os
import shutil
import psutil
import base64

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
PUB = '/usr/share/wordpress/sads.hash'


def port_not_used(lport):
	lport = str(lport)
	for connection in psutil.net_connections():
		host, port = connection.laddr
		if host == '0.0.0.0' and str(port) == lport:
			return False
	return True


def meha(prehash):
	hash1 = hashlib.md5(prehash.encode("UTF-8")).hexdigest()
	hash2 = hashlib.sha256(hash1.encode("UTF-8")).hexdigest()
	hash3 = hashlib.sha384(hash2.encode("UTF-8")).hexdigest()
	hash4 = hashlib.sha512(hash3.encode("UTF-8")).hexdigest()
	hash5 = hashlib.sha384(hash4.encode("UTF-8")).hexdigest()
	hash6 = hashlib.sha256(hash5.encode("UTF-8")).hexdigest()
	hash7 = hashlib.sha224(hash6.encode("UTF-8")).hexdigest()
	return hash7


def meha_salt(prehash):
	salts = [''.join([random.choice(string.printable) for _ in range(40)]) for _ in range(int(7))]

	hash1 = hashlib.md5((prehash + salts[0]).encode("UTF-8")).hexdigest()
	hash2 = hashlib.sha256((hash1 + salts[1]).encode("UTF-8")).hexdigest()
	hash3 = hashlib.sha384((hash2 + salts[2]).encode("UTF-8")).hexdigest()
	hash4 = hashlib.sha512((hash3 + salts[3]).encode("UTF-8")).hexdigest()
	hash5 = hashlib.sha384((hash4 + salts[4]).encode("UTF-8")).hexdigest()
	hash6 = hashlib.sha256((hash5 + salts[5]).encode("UTF-8")).hexdigest()
	hash7 = hashlib.sha224((hash6 + salts[6]).encode("UTF-8")).hexdigest()
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
	temp = open(TEMP, 'w')
	sshd = open(SSHD_CONFIG, 'r')
	for line in sshd:
		line = line.strip('\n')
		if '#SADS_SERVICE_TAG' in line:
			pass
		else:
			temp.write(line + '\n')
	temp.write('Port ' + str(port) + '  #SADS_SERVICE_TAG\n')
	temp.close()
	sshd.close()
	shutil.move(TEMP, SSHD_CONFIG)
	os.system('service ssh restart')


def publish_hash(shash):
	if os.path.isfile(PUB):
		os.remove(PUB)
	with open(PUB, 'w') as pub:
		pub.write(shash)
	pub.close()


while True:
	shash = meha_salt('sads project')
	port = get_port(shash) + get_port(meha(shash))
	shash = base64.b64encode(shash.encode('utf-8')).decode('utf-8')
	print(Y + '[+] INFO: Changing to Port: ' + G + str(port) + W)
	set_port(port)
	print(Y + '[+] INFO: Changed!' + W)
	print(Y + '[+] INFO: Publishing Hash: ' + G + str(shash) + W)
	publish_hash(shash)
	print(Y + '[+] INFO: Published!' + W)
	for x in range(10, 0, -1):
		print(P + BD + '\r[#] SADS: Next Change in ' + C + str(x) + P + ' Seconds ' + W, end='')
		time.sleep(1)
	print('\r                                  \r', end='')
