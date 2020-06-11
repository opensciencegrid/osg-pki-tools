#!/usr/bin/python

import getpass
import os
import sys
import tempfile

from M2Crypto import SSL, m2, RSA, EVP, X509

from ExceptionDefinitions import *
from osgpkitools import utils


# These flags are for the purpose of passing to the M2Crypto calls
MBSTRING_FLAG = 0x1000
MBSTRING_ASC = MBSTRING_FLAG | 1
MBSTRING_BMP = MBSTRING_FLAG | 2


def get_ssl_context(usercert, userkey):
    """ This function sets the ssl context by accepting the passphrase
    and validating it for user private key and his certificate
    INPUT
        cert: Filename for user certificate.
        key: Filename for private key of user.

    OUTPUT
        SSL.Context() object for the HTTPS connection.
    """
    pass_str = 'Please enter the pass phrase for'
    for _ in range(0, 2): # allow two password attempts
        def prompt_for_password(verify):
            return getpass.getpass(pass_str+" '%s':" % userkey)

        ssl_context = SSL.Context()
        ssl_context.set_options(m2.SSL_OP_NO_SSLv2 | m2.SSL_OP_NO_SSLv3)

        try:
            ssl_context.load_cert_chain(usercert, userkey, callback=prompt_for_password)
            return ssl_context
        except SSL.SSLError as exc:
            if 'bad decrypt' in exc:
                pass_str = 'Incorrect password. Please enter the password again for'
            else:
                raise

    # if we fell off the loop, the passphrase was incorrect twice
    raise BadPassphraseException('Incorrect passphrase. Attempt failed twice.')


class Csr(object):

    KEY_LENGTH = 2048
    PUB_EXPONENT = 0x10001

    def __init__(self, hostname, output_dir=None, altnames=None, location=None):
        """
        Create a certificate signing request (CSR - stored in the x509request attribute) and associated keys (stored in keypair attribute).
       
        The caller should use write_csr to write CSR when ready. 
        The caller should use write_pkey to write private key when ready.
  
        INPUT
            - hostname: common name for the CN field 
            - output_dir (optional): The destination directory to write the request and key
            - altnames (optional): Additional hostnames to be added to the Subject Alternative Names.
            - location (optional): A namedtuple containing country (e.g., US), state (e.g., Wisconsin),
            locality (e.g., Madison), and organization (e.g., University of Wisconsin)
        """
        self.output_dir = output_dir
        # TODO this check should come from the main commands
        if not output_dir:
            self.output_dir = os.getcwd()

        # Set up CSR and PKEY file paths 
        self.csrpath = os.path.join(output_dir, hostname + '.req')
        self.keypath = os.path.join(output_dir, hostname + '-key.pem')

        self.keypair = RSA.gen_key(self.KEY_LENGTH,  self.PUB_EXPONENT, lambda: None)
        
        # The message digest shouldn't matter here since we don't use
        # PKey.sign_*() or PKey.verify_*() but there's no harm in keeping it and
        # it ensures a strong hashing algo (default is sha1) if we do decide to
        # sign things in the future
        self.pkey = EVP.PKey(md='sha256')
        self.pkey.assign_rsa(self.keypair)

        self.x509request = X509.Request()
        x509name = X509.X509_Name()
        
        # Build entries for x509 name
        entries = list()

        if location:
            entries.append(('C', location.country))
            entries.append(('ST', location.state))
            entries.append(('L', location.locality))
            entries.append(('O', location.organization))
            for ou in location.organizational_unit:
                entries.append(('OU', ou))

        entries.append(('CN', hostname))
        
        for key, val in entries:
            x509name.add_entry_by_txt(field=key, type=MBSTRING_ASC, entry=val, len=-1, loc=-1, set=0)

        self.x509request.set_subject_name(x509name)
        
        # Build altnames
        self.altnames = None

        if altnames:
            str_altnames= ",".join(altnames)
            self.altnames = str_altnames
            extension_stack = X509.X509_Extension_Stack()
            extension = X509.new_extension('subjectAltName',
                                           ", ".join(['DNS:%s' % name for name in altnames]))
            extension.set_critical(1)
            extension_stack.push(extension)
            self.x509request.add_extensions(extension_stack)

        # Set up pubkey and sign CSR with privkey
        self.x509request.set_pubkey(pkey=self.pkey)
        self.x509request.set_version(0)
        self.x509request.sign(pkey=self.pkey, md='sha256')
    
    def write_csr(self, csrpath=None):
        """Write the certificate signing request"""
        if not csrpath:
            csrpath = self.csrpath

        try:
            utils.safe_write(csrpath, self.x509request.as_pem())
        except:
            os.remove(self.keypath) # if we can't write the CSR, remove its associated private key
            raise

    def write_pkey(self, keypath=None):
        """Write the instance's private key to keypath, backing up keypath to keypath.old if necessary"""
        if not keypath:
            keypath = self.keypath

        # Handle already existing key file...
        utils.safe_rename(keypath)

        # this is like atomic_write except writing with save_key
        temp_fd, temp_name = tempfile.mkstemp(dir=self.output_dir)
        os.close(temp_fd)
        os.chmod(temp_name, 0o600)
        self.keypair.save_key(temp_name, cipher=None)
        os.rename(temp_name, keypath)

    def format_csr(self, csr):
        """Extract the base64 encoded string from the contents of a CSR"""
        return csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '')\
                .replace('-----END CERTIFICATE REQUEST-----\n', '')\
                .replace('\n', '')

    def base64_csr(self):
        """Extract the base64 encoded string from the contents of a certificate signing request"""
        return self.format_csr(self.x509request.as_pem())


 



    
