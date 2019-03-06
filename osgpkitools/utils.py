#!/usr/bin/python

import ConfigParser
import errno
import os
import re
import time
import shutil
import sys
import tempfile
import textwrap
import json
import signal
import subprocess
import traceback
import getpass
from StringIO import StringIO
from M2Crypto import SSL, m2, RSA, EVP, X509

#This code is hosted at from https://github.com/opensciencegrid/osg-pki-tools/blob/v2.1.4/osgpkitools/OSGPKIUtils.py
#Author Brian Lin - blin@cs.wisc.edu

# These flags are for the purpose of passing to the M2Crypto calls and are used later in the script

MBSTRING_FLAG = 0x1000
MBSTRING_ASC = MBSTRING_FLAG | 1
MBSTRING_BMP = MBSTRING_FLAG | 2

DEFAULT_CONFIG = """[InCommon]

organization: 9697
department: 9732
customeruri: InCommon
igtfservercert: 215
igtfmultidomain: 283
servertype: -1
term: 395
apiurl: cert-manager.com
listingurl: /private/api/ssl/v1/types
enrollurl: /private/api/ssl/v1/enroll  
retrieveurl: /private/api/ssl/v1/collect/
sslid: sslId
certx509: /x509
certx509co: /x509CO
certbase64: /base64
certbin: /bin
content_type: application/json
"""


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
            if 'bad password read' in exc:
                pass_str = 'Incorrect password. Please enter the password again for'
            else:
                raise

    # if we fell off the loop, the passphrase was incorrect twice
    raise BadPassphraseException('Incorrect passphrase. Attempt failed twice. Exiting script')


def charlimit_textwrap(string):
    """This function wraps up the output to 80 characters. Accepts string and print the wrapped output"""

    list_string = textwrap.wrap(str(string), width=80)
    for line in list_string:
        print(line)
    return


def print_exception_message(exc):
    """Checks if the str representation of the exception is empty or not
    if empty, it prints an generic error message stating the type of exception
    and traceback.
    """

    if str(exc) != "":
        charlimit_textwrap("Got an exception %s" % exc.__class__.__name__)
        charlimit_textwrap(exc)
        #charlimit_textwrap('Please report the bug to %s.' % HELP_EMAIL)
    else:
        handle_empty_exceptions(exc)


def handle_empty_exceptions(exc):
    """The method handles all empty exceptions and displays a meaningful message and
    traceback for such exceptions."""

    print(traceback.format_exc())
    charlimit_textwrap('Encountered exception of type %s' % exc.__class__.__name__)
    #charlimit_textwrap('Please report the bug to %s.' % HELP_EMAIL)


def format_csr(csr):
    """Extract the base64 encoded string from the contents of a CSR"""
    return csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '')\
              .replace('-----END CERTIFICATE REQUEST-----\n', '')\
              .replace('\n', '')


def atomic_write(filename, contents):
    """Write to a temporary file then move it to its final location
    """
    temp_fd, temp_name = tempfile.mkstemp(dir=os.path.dirname(filename))
    os.write(temp_fd, contents)
    os.close(temp_fd)
    os.rename(temp_name, filename)


def check_response_500(response):
    """ This functions handles the 500 error response from the server"""

    if response.status == 500:
        raise Exception_500response(response.status, response.reason)


def read_config():
    config_path = r'config.ini'
    config = ConfigParser.ConfigParser()
    
    if not config.read(config_path):
        config.readfp(StringIO(DEFAULT_CONFIG))
    
    return dict(config.items('InCommon'))


def safe_rename(filename):
    """Renames 'filename' to 'filename.old'
    """
    old_filename = filename + '.old'
    try:
        shutil.move(filename, old_filename)
        print "Renamed existing file from %s to %s" % (filename, old_filename)
    except IOError, exc:
        if exc.errno != errno.ENOENT:
            charlimit_textwrap(exc.message)
            raise RuntimeError('ERROR: Failed to rename %s to %s' % (filename, old_filename))


def check_permissions(path):
    """The function checks for write permissions for the given path to verify if the user has write permissions
    """
    if os.access(path, os.W_OK):
        return
    else:
        raise FileWriteException("User does not have appropriate permissions for writing to current directory.")


def find_user_cred(usercert=None, userkey=None):
    """Find a readable user cert/key pair, trying pairs in the following order:
    1. usercert, userkey
    2. X509_USER_CERT, X509_USER_KEY environment variables
    3. '~/.globus/usercert.pem', '~/.globus/userkey.pem'
    INPUT (optional)
    usercert: path to user certificate
    userkey: path to private key of user
    OUTPUT
    Paths to the user cert and key
    """
    
    # list of cert/key pairs to try
    input_pairs = [(usercert, userkey),
                   ((os.environ.get('X509_USER_CERT'), os.environ.get('X509_USER_KEY'))),
                   (os.path.expanduser('~/.globus/usercert.pem'), os.path.expanduser('~/.globus/userkey.pem'))]
    cert_key_pairs = [t for t in input_pairs if None not in t] # remove undefined pairs for an improved err msg below

    # M2Crypto doesn't raise exceptions when encountering missing or unreadable
    # cert/key pairs so we force the issue
    for cert, key in cert_key_pairs:
        try:
            open(cert, 'r')
            open(key, 'r')
            return cert, key
        except IOError:
            continue
    raise IOError("Unable to read the following certificate/key pairs:\n- %s" %
                  "\n- ".join([", ".join(pair) for pair in cert_key_pairs]))


def print_failure_reason_exit(data):
    """This functions prints the failure reasons and exits"""
    try:
        msg = 'The request has failed for the following reason: %s' % \
        json.loads(data)['detail'].split('--')[1].lstrip()
    except IndexError:
        msg = 'The request has failed for the following reason: %s' % json.loads(data)['detail'].lstrip() + \
              'Status : %s ' % json.loads(data)['status']

    separator = '='*80
    sys.exit('\n'.join(textwrap.wrap(separator + msg, width=80)))


class Cert(object):

    KEY_LENGTH = 2048
    PUB_EXPONENT = 0x10001

    def __init__(self, common_name, output_dir=None, altnames=None):
        """Create a certificate request (stored in the x509request attribute) and associated keys (stored in keypair attribute).
        The caller should use write_pkey to write private key when ready.

        This function accepts the CN and final path for the key as well as optional list of subject alternative names
        and optional requestor e-mail.  """
        escaped_common_name = common_name.replace('/', '_') # Remove / from service requests for writing keys
        self.keypair = RSA.gen_key(self.KEY_LENGTH,
                                   self.PUB_EXPONENT,
                                   self.callback)

        if not output_dir:
            output_dir = os.getcwd()
        self.output_dir = output_dir
        self.final_keypath = os.path.join(output_dir, escaped_common_name + '-key.pem')
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
