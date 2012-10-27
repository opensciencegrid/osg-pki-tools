#!/usr/bin/env python
#
#vim: ts=4 sw=4 nowrap
#

import M2Crypto
import base64

MBSTRING_FLAG = 0x1000
MBSTRING_ASC  = MBSTRING_FLAG | 1
MBSTRING_BMP  = MBSTRING_FLAG | 2

def CreateOIMConfig (isITB, **OIMConfig):
	OIMConfig.update({'requrl': '/oim/rest?action=host_certs_request&version=1'})
	OIMConfig.update({'appurl': '/oim/rest?action=host_certs_approve&version=1'})
	OIMConfig.update({'revurl': '/oim/rest?action=host_certs_revoke&version=1'})
	OIMConfig.update({'canurl': '/oim/rest?action=host_certs_cancel&version=1'})
	OIMConfig.update({'returl': '/oim/rest?action=host_certs_retrieve&version=1'})
	OIMConfig.update({'issurl': '/oim/rest?action=host_certs_issue&version=1'})
	OIMConfig.update({'content_type': 'application/x-www-form-urlencoded'})
	if (isITB):
		OIMConfig.update({'host': 'oim-itb.grid.iu.edu:80'})
		OIMConfig.update({'hostsec': 'oim-itb.grid.iu.edu:443'})
	else:
		OIMConfig.update({'host': 'oim.grid.iu.edu:80'})
		OIMConfig.update({'hostsec': 'oim.grid.iu.edu:443'})
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
	#run.CreateX509Certificate ()