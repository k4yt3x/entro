#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""
 .d8888b.        d8888 8888888b.   .d8888b.
d88P  Y88b      d88888 888  "Y88b d88P  Y88b
Y88b.          d88P888 888    888 Y88b.
 "Y888b.      d88P 888 888    888  "Y888b.
    "Y88b.   d88P  888 888    888     "Y88b.
      "888  d88P   888 888    888       "888
Y88b  d88P d8888888888 888  .d88P Y88b  d88P
 "Y8888P" d88P     888 8888888P"   "Y8888P"



Name: SADS Active Defence System
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

TODO:
1. Complete Tor connections for urllib

"""

from __future__ import print_function
import urllib.request
import socket
import os
import base64
import argparse
import time
import hashlib

SERVER_ADDRESS = '127.0.0.1'


# -------------------------------- Classes Defining --------------------------------

class ccm():
	"""
		This Class defines some output styles and
		All UNIX colors
	"""

	# Define Global Color
	global W, R, G, OR, Y, B, P, C, GR, H, BD, NH
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
	BD = '\033[1m'  # Bold
	NH = '\033[28m'  # not hidden

	def __init__(self, arg):
		super(ccm, self).__init__()
		self.arg = arg

	def info(msg):
		print(G + '[+] INFO: ' + str(msg) + W)

	def warning(msg):
		print(Y + BD + '[!] WARNING: ' + str(msg) + W)

	def error(msg):
		print(R + BD + '[!] ERROR: ' + str(msg) + W)

	def debug(msg):
		print(R + BD + '[*] DBG: ' + str(msg) + W)


# -------------------------------- Functions Defining --------------------------------

def process_arguments():
	"""
	This funtion takes care of all arguments
	"""
	global args
	parser = argparse.ArgumentParser()
	action_group = parser.add_argument_group('ACTIONS')
	action_group.add_argument("-s", "--sftp", help="-f, --sftp: Connect SFTP", action="store_true", default=False)
	action_group.add_argument("-d", "--debug", help="-d, --debug: Debug port connection and decryption; decrypt port but don't connect", action="store_true", default=False)
	action_group.add_argument("-u", "--username", help="-u, --username [username]: Choose which user to connect as", action="store", default="root")
	action_group.add_argument("--tor", help="--tor : Connect Using tor", action="store_true", default=False)
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
	hash7 = hashlib.sha224(hash6.encode("UTF-8")).hexdigest()
	return hash7


def get_hash():
	if args.debug:
		internet = internet_connected()
		if internet:
			with urllib.request.urlopen('WEBSITE HASH FILE') as response:
				hash = response.read().decode().split('\n')[0]
				ccm.debug(hash)
				return hash
		else:
			ccm.error('Internet Not Connected!')
			ccm.error('Aborting...')
			exit(1)
	elif args.tor:
		internet = internet_connected()
		print(Y + '[+] INFO: ' + W + 'Getting Hash From Server..........', end='')
		if internet:
			with urllib.request.urlopen('WEBSITE HASH FILE') as response:
				hash = response.read().decode().split('\n')[0]
				print(G + 'OK!' + W)
				print(G + '[+] INFO: Got Hash: ' + str(hash) + W)
				return hash
		else:
			ccm.error('Internet Not Connected!')
			ccm.error('Aborting...')
			exit(1)
	else:
		internet = internet_connected()
		print(Y + '[+] INFO: ' + W + 'Getting Hash From Server..........', end='')
		if internet:
			with urllib.request.urlopen('WEBSITE HASH FILE') as response:
				hash = response.read().decode().split('\n')[0]
				print(G + 'OK!' + W)
				print(G + '[+] INFO: Got Hash: ' + str(hash) + W)
				return hash
		else:
			ccm.error('Internet Not Connected!')
			ccm.error('Aborting...')
			exit(1)


def get_port(hash):
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
	print(Y + '[+] INFO: ' + W + 'Checking Internet.................' + W, end='')
	try:
		socket.create_connection(('SERVER ADDRESS', 443), 5)  # Test connection by connecting to google
		print(G + 'OK!' + W)
		return True
	except socket.error:
		print(R + 'NO INTERNET!' + W)
		return False


def refresh(delay):
	"""
		Pause the program for [delay] seconds

	Arguments:
		delay {int} -- the amount of time to pause
	"""
	for x in range(delay, 0, -1):
		print(P + BD + '\r[#] SADS: Next Refresh in ' + C + str(x) + P + ' Seconds ' + W, end='')
		time.sleep(1)
	print('\r                                  \r', end='')


# -------------------------------- Procedural Code --------------------------------

process_arguments()

hash = get_hash()
hash = base64.b64decode(hash.encode('utf-8')).decode('utf-8')

port = get_port(hash) + get_port(meha(hash))

if args.debug:
	ccm.info(R + BD + 'Debug Mode Enabled')
	ccm.info(R + BD + 'Continuely Printing Server info')
	while True:
		hash = get_hash()
		hash = base64.b64decode(hash.encode('utf-8')).decode('utf-8')
		port = get_port(hash) + get_port(meha(hash))
		ccm.debug('Port Number Decrypted: ' + Y + BD + str(port))
		refresh(5)
elif args.sftp and args.tor:
	ccm.info(BD + 'Connecting Using SFTP')
	ccm.info(BD + 'Connecting using Tor')
	os.system('proxychains sftp -P ' + port + ' -o StrictHostKeyChecking=no root@SERVER_ADDRESS')
elif args.sftp:
	ccm.info(BD + 'Connecting Using SFTP')
	os.system('sftp -P ' + port + ' -o StrictHostKeyChecking=no root@SERVER_ADDRESS')
elif args.tor:
	ccm.info('Port Number Decrypted: ' + BD + OR + port)
	ccm.info(BD + 'Connecting to SSH')
	ccm.info(BD + 'Connecting using Tor')
	os.system('proxychains ssh -p ' + port + ' ' + args.username + '@SERVER_ADDRESS -o StrictHostKeyChecking=no')
else:
	ccm.info('Port Number Decrypted: ' + BD + OR + port)
	ccm.info(BD + 'Connecting to SSH')
	os.system('ssh -p ' + port + ' ' + args.username + '@SERVER_ADDRESS -o StrictHostKeyChecking=no')
