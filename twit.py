#
# twit.py
# Copyright 2009 Kaerast <kaerast@qvox.org>
# 
# This file uses copyrighted code from Google, but otherwise use as you like
# No gaurantees that it isn't terribly insecure
"""
This script publishes a blowfish encrypted message to twitter
It can also decrypt a manually entered message from twitter
Send questions, comments, bugs my way:
	http://privacybox.de/kaerast.msg
"""
# import standard libs
import binascii
import getopt
import sys
# import included libs
sys.path.append("./lib")
from blowfish import Blowfish
import twitter

# Set up twitter account here. Sure it's insecure, but now we're using encryption who cares?
twitter_user = 'myusername'
twitter_password = 'mypassword'

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "k:m:d", ["key=", "message=", "decrypt"])
	except getopt.GetoptError, err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage()
		sys.exit(2)
	key = ''
	text = ''
	decrypt = False
	for o, a in opts:
		if o in ("-m", "--message"):
			text = a
		elif o in ("-k", "--key"):
			key = a
			keylen = len(key)
			if keylen not in (8,16,24,32,40,48,56):
				print "\tKey must be a multiple of 8 bytes (up to a maximum of 56"
				sys.exit(3)
		elif o in ("-d", "--decrypt"):
			decrypt = True
		else:
			assert False, "unhandled option"
	cipher = Blowfish(key)
	cipher.initCTR()
	if decrypt == False:
		crypted = binascii.hexlify(cipher.encryptCTR(text))
		if (len(crypted) < 140):
			client = twitter.Api(username=twitter_user, password=twitter_password)
			update = client.PostUpdate(crypted)
		else:
			print "\tYour message was too long, it should be less than 140 characters. It was\t", len(crypted)
		print "\tEncrypted message:\t", crypted
	else:
		decrypted = cipher.decryptCTR(binascii.unhexlify(text))
		print "\tDecrypted message:\t", decrypted

def usage():
	print "\tUsage:\t twit.py [--decrypt] --message=\"My message\" --key=key"
	print "\tOptions can also be passed in short form as [-d] -m and -k"
	print "\tThe key must be a multiple of 8 bytes (up to a maximum of 56)."
if __name__ == "__main__":
    main()

