#!/usr/bin/python

import os
import sys

from M2Crypto import SSL, m2, RSA, EVP, X509

from ExceptionDefinitions import *

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
        except SSL.SSLError, exc:
            if 'bad decrypt' in exc:
                pass_str = 'Incorrect password. Please enter the password again for'
            else:
                raise

    # if we fell off the loop, the passphrase was incorrect twice
    raise BadPassphraseException('Incorrect passphrase. Attempt failed twice.')


class Csr(object):

    KEY_LENGTH = 2048
    PUB_EXPONENT = 0x10001

    def __init__(self, common_name, output_dir=None, altnames=None):
        """Create a certificate request (stored in the x509request attribute) and associated keys (stored in keypair attribute).
        The caller should use write_pkey to write private key when ready.

        This function accepts the CN and final path for the key as well as optional list of subject alternative names
        and optional requestor e-mail.  """
        self.keypair = RSA.gen_key(self.KEY_LENGTH,
                                   self.PUB_EXPONENT,
                                   self.callback)

        if not output_dir:
            output_dir = os.getcwd()
        self.output_dir = output_dir
        self.final_keypath = os.path.join(output_dir, common_name + '-key.pem')
        # The message digest shouldn't matter here since we don't use
        # PKey.sign_*() or PKey.verify_*() but there's no harm in keeping it and
        # it ensures a strong hashing algo (default is sha1) if we do decide to
        # sign things in the future
        self.pkey = EVP.PKey(md='sha256')
        self.pkey.assign_rsa(self.keypair)

        self.x509request = X509.Request()
        x509name = X509.X509_Name()

        x509name.add_entry_by_txt(  # common name
            field='CN',
            type=MBSTRING_ASC,
            entry=common_name,
            len=-1,
            loc=-1,
            set=0,
            )

        self.x509request.set_subject_name(x509name)
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

        self.x509request.set_pubkey(pkey=self.pkey)
        self.x509request.set_version(0)
        self.x509request.sign(pkey=self.pkey, md='sha256')

    def callback(self, *args):
        return None

    def write_pkey(self, keypath=None):
        """Write the instance's private key to keypath, backing up keypath to keypath.old if necessary"""
        if not keypath:
            keypath = self.final_keypath

        # Handle already existing key file...
        safe_rename(keypath)

        # this is like atomic_write except writing with save_key
        temp_fd, temp_name = tempfile.mkstemp(dir=self.output_dir)
        os.close(temp_fd)
        self.keypair.save_key(temp_name, cipher=None)
        os.rename(temp_name, keypath)

    def base64_csr(self):
        """Extract the base64 encoded string from the contents of a certificate signing request"""
        return format_csr(self.x509request.as_pem())
