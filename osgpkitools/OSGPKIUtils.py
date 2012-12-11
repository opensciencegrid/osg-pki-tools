#!/usr/bin/env python
#
#vim: ts=4 sw=4 nowrap
#

import M2Crypto
import base64
import ConfigParser
import os

MBSTRING_FLAG = 0x1000
MBSTRING_ASC  = MBSTRING_FLAG | 1
MBSTRING_BMP  = MBSTRING_FLAG | 2


def charlimit_textwrap(string):
    """This function wraps up tht output to 80 characters. Accepts string and print the wrapped output"""
    list_string = textwrap.wrap(string)
    for line in list_string:
        print line
    return

def get_request_count(filename):
	'''Returns the number of request in the file'''
	hostfile = open(filename, 'rb')
	name_set = set()
	count = 0
	for line in hostfile.readlines():
		line = line.strip(' \n')
		if not line in name_set:
			name_set.add(line)
			count +=1
	return count

def extractHostname(certString):
	#Extracts hostname from the string of certifcate file"""
	certArray = certString.split(' ')
	hostname = ""
	for subStr in certArray:
		if '/CN=' in subStr:
			if not 'DigiCert' in subStr.split('/CN=')[1].split('\n')[0]:
				hostname = subStr.split('/CN=')[1].split('\n')[0]
			
	return hostname

def extractEEM(certString, hostname):
	certArray = certString.split('\n\n')
	for certArrayString in certArray: 
		if (hostname in certArrayString):
			return certArrayString

		
def CreateOIMConfig (isITB, **OIMConfig):
	Config = ConfigParser.ConfigParser()
	if os.path.exists(str(os.environ['HOME'])+'/.osg-pki/OSG_PKI.ini'):
		print "Overriding INI file with %s/.osg-pki/OSG_PKI.ini" %str(os.environ['HOME'])
		Config.read('pki-clients.ini')
	elif os.path.exists('pki-clients.ini'):
		Config.read('pki-clients.ini')
	elif os.path.exists('/etc/pki-clients.ini'):
		Config.read('/etc/pki-clients.ini')
	else:
		sys.exit('Missing config file: pki-clients.ini\n')
	if isITB:
		print "Running in test mode"
		OIM = 'OIMData_ITB'
		OIMConfig.update({'host': 'oim-itb.grid.iu.edu:80'})
		OIMConfig.update({'hostsec': 'oim-itb.grid.iu.edu:443'})
	else:
		OIM = 'OIMData'
		OIMConfig.update({'host': 'oim.grid.iu.edu:80'})
		OIMConfig.update({'hostsec': 'oim.grid.iu.edu:443'})
	OIMConfig.update({'requrl': Config.get(OIM, 'requrl')})
	OIMConfig.update({'appurl': Config.get(OIM, 'appurl')})
	OIMConfig.update({'revurl': Config.get(OIM, 'revurl')})
	OIMConfig.update({'canurl': Config.get(OIM, 'canurl')})
	OIMConfig.update({'returl': Config.get(OIM, 'returl')})
	OIMConfig.update({'issurl': Config.get(OIM, 'issurl')})
	OIMConfig.update({'quotaurl': Config.get(OIM, 'quotaurl')})
	OIMConfig.update({'content_type': Config.get(OIM, 'content_type')})
	return OIMConfig

class Cert:
	def __init__ ( self ):
		self.RsaKey = { 'KeyLength'       : 2048,
						'PubExponent'     : 0x10001,		# -> 65537
						'keygen_callback' : self.callback 
				  }

		self.KeyPair         = None
		self.PKey            = None

		self.X509Request     = None 
		self.X509Certificate = None

	def callback ( self, *args ):
		return None


	def CreatePKey ( self , filename ):
		"""This function accepts the filename of the key file to write to.
		It write the private key to the specified file name without ciphering it."""
		self.KeyPair = M2Crypto.RSA.gen_key( self.RsaKey['KeyLength'], self.RsaKey['PubExponent'], self.RsaKey['keygen_callback'] )
		PubKey = M2Crypto.RSA.new_pub_key( self.KeyPair.pub () )
		self.KeyPair.save_key( filename, cipher=None)
		self.PKey = M2Crypto.EVP.PKey ( md='sha1')
		self.PKey.assign_rsa ( self.KeyPair )


	def CreateX509Request ( self, **config_items ):
		"""This function accepts a dctionary that contains information regarding the CSR.
		It creates a CSR and returns it to the calling script."""
		#
		# X509 REQUEST
		#

		self.X509Request = M2Crypto.X509.Request ()

		#
		# subject
		#

		X509Name = M2Crypto.X509.X509_Name ()

		X509Name.add_entry_by_txt ( field='CN',           type=MBSTRING_ASC, entry=config_items['CN'],    len=-1, loc=-1, set=0 )    # common name
		if config_items.has_key('emailAddress'):
			X509Name.add_entry_by_txt ( field='emailAddress', type=MBSTRING_ASC, entry=config_items['emailAddress'],        len=-1, loc=-1, set=0 )    # pkcs9 email address     

		self.X509Request.set_subject_name( X509Name )
		#
		# publickey
		#
		self.X509Request.set_pubkey ( pkey=self.PKey )
		self.X509Request.sign ( pkey=self.PKey, md = 'sha1')
		return self.X509Request



if __name__ == '__main__':
	run = Cert()
	run.CreatePKey()
	run.CreateX509Request()