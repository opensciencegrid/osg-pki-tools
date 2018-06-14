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

from ExceptionDefinitions import *

# These flags are for the purpose of passing to the M2Crypto calls and are used later in the script

MBSTRING_FLAG = 0x1000
MBSTRING_ASC = MBSTRING_FLAG | 1
MBSTRING_BMP = MBSTRING_FLAG | 2

# The variable for storing version number for the scripts
VERSION_NUMBER = "2.1.4"

HELP_EMAIL = 'help@opensciencegrid.org'

DEFAULT_CONFIG = """[OIMData_ITB]
host: oim-itb.grid.iu.edu:80
hostsec: oim-itb.grid.iu.edu:443

[OIMData]
host: oim.grid.iu.edu:80
hostsec: oim.grid.iu.edu:443

[DEFAULT]
requrl: /oim/rest?action=host_certs_request&version=1
appurl: /oim/rest?action=host_certs_approve&version=1
revurl: /oim/rest?action=host_certs_revoke&version=1
canurl: /oim/rest?action=host_certs_cancel&version=1
returl: /oim/rest?action=host_certs_retrieve&version=1
issurl: /oim/rest?action=host_certs_issue&version=1
content_type: application/x-www-form-urlencoded
renewurl: /oim/rest?action=user_cert_renew&version=1
userreturl: /oim/rest?action=user_cert_retrieve&version=1
userrevurl: /oim/rest?action=user_cert_revoke&version=1
"""

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


def print_exception_message(exc):
    """Checks if the str representation of the exception is empty or not
    if empty, it prints an generic error message stating the type of exception
    and traceback.
    """

    if str(exc) != "":
        charlimit_textwrap("Got an exception %s" % exc.__class__.__name__)
        charlimit_textwrap(exc)
        charlimit_textwrap('Please report the bug to %s.' % HELP_EMAIL)
    else:
        handle_empty_exceptions(exc)

def print_uncaught_exception():
    """This function prints the stack trace of a failure to aid
    debugging"""
    print traceback.format_exc()

def handle_empty_exceptions(exc):
    """The method handles all empty exceptions and displays a meaningful message and
    traceback for such exceptions."""

    print traceback.format_exc()
    charlimit_textwrap('Encountered exception of type %s' % exc.__class__.__name__)
    charlimit_textwrap('Please report the bug to %s.' % HELP_EMAIL)

def version_info():
    """ Print the version number and exit"""
    print "OSG CLI Scripts Version :", VERSION_NUMBER

def check_permissions(path):
    """The function checks for write permissions for the given path to verify if the user has write permissions
    """
    if os.access(path, os.W_OK):
        return
    else:
        raise FileWriteException("User does not have appropriate permissions for writing to current directory.")

def find_existing_file_count(filename):
    '''Check if filename and revisions of the filename exists. If so, increment the revision number and return
    the latest revision filename'''
    temp_name = filename.split(".")[-2]
    trimmed_name = temp_name
    version_count = 0
    if os.path.exists(filename):
        while os.path.exists(temp_name + '.pem'):
            if version_count == 0:
                temp_name = temp_name +'-'+str(version_count)
            else:
                temp_name = trimmed_name
                temp_name = temp_name + '-' + str(version_count)
            version_count = version_count + 1

    if version_count > 0:
        version_count -= 1
        new_file = trimmed_name + '-' +str(version_count) + '.pem'
        return new_file
    else:
        return filename

def check_response_500(response):
    """ This functions handles the 500 error response from the server"""

    if response.status == 500:
        raise Exception_500response(response.status, response.reason)


def check_failed_response(data):
    """ This function checks if the response is failed"""

    if 'FAILED' in data:
        print_failure_reason_exit(data)


def print_failure_reason_exit(data):
    """This functions prints the failure reasons and exits"""
    try:
        msg = 'The request has failed for the following reason: %s' % \
              json.loads(data)['detail'].split('--')[1].lstrip()
    except IndexError:
        msg = 'The request has failed for the following reason: %s' % json.loads(data)['detail'].lstrip() + \
              'Status : %s ' % json.loads(data)['status']

    # Print a helpful error message if OIM responds that the user needs to
    # provide a VO in their request. We cannot handle this in the arg parsing
    # because not all domains require VO information (SOFTWARE-2292)
    if re.search(r'Couldn\'t find GridAdmin group under specified VO', msg):
        msg = "Failed to request certificate due to bad VO information. " + \
              "Did you specify an acceptable VO for your requested domain? " + \
              "See http://oim.opensciencegrid.org/oim/gridadmin for a list of VOs per domain"
    separator = '='*80
    sys.exit('\n'.join(textwrap.wrap(separator + msg, width=80)))


def check_for_pending(iterations):
    """ This function is a centralized location to print the in process output indication"""

    time.sleep(5)
    iterations = iterations + 1
    if iterations % 6 == 0:
        print '.',
        sys.stdout.flush()
    return iterations

def sigalrm_handler(signum, frame):
    """Exit when SIGALRM is raised (handler functions must take signum and frame args)"""
    sys.exit('Exiting due to timeout')

def start_timeout_clock(minutes):
    """Initiates a timer that exits the process with return code 1 after 'minutes'"""
    seconds = minutes*60
    signal.signal(signal.SIGALRM, sigalrm_handler)
    if seconds == 0: # Work around signal.alarm(0) cancelling the signal timer
        os.kill(os.getpid(), signal.SIGALRM)
    else:
        signal.alarm(seconds)

def charlimit_textwrap(string):
    """This function wraps up the output to 80 characters. Accepts string and print the wrapped output"""

    list_string = textwrap.wrap(str(string), width=80)
    for line in list_string:
        print line
    return

def format_csr(csr):
    """Extract the base64 encoded string from the contents of a CSR"""
    return csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '')\
              .replace('-----END CERTIFICATE REQUEST-----\n', '')\
              .replace('\n', '')

def atomic_write(filename, contents):
    """Write to a temporary file then move it to its final location
    """
    temp_file = tempfile.NamedTemporaryFile(dir=os.path.dirname(filename))
    temp_file.write(contents)
    temp_file.flush()
    shutil.copy2(temp_file.name, filename)

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

def extract_certs(pkcs7raw):
    """This function accepts pkcs7raw dump of a single certificate and
    extracts the host certificate in PEM format. Returns a tuple of
    strings: (hostname, certificate)
    """
    pkcs7_file = tempfile.NamedTemporaryFile()
    pkcs7_file.write(str(pkcs7raw))
    pkcs7_file.flush()
    pem_file = tempfile.NamedTemporaryFile()

    # ### printing our all the certificates received from OIM to a temporary file###
    subprocess.call([
        'openssl',
        'pkcs7',
        '-print_certs',
        '-in',
        os.path.abspath(pkcs7_file.name),
        '-out',
        os.path.abspath(pem_file.name),
        ])
    pkcs7_file.close()
    cert_string = pem_file.read()
    pem_file.close()

    hostname = extractHostname(cert_string)
    eec_string = extractEEC(cert_string, hostname)

    return (hostname, eec_string)

### We take the whole certificate data as a string input
### Checking for /CN= in every line and extracting the term after that if not Digicert i.e. CA would be the hostname
### Here we rely on OPenSSL -printcert output format. If it changes our output might be affected

def extractHostname(cert_string):
    """Extracts hostname from the string of certificate file
    We take the whole certificate data as a string input
    Checking for /CN= in every line and extracting the term after that if not Digicert i.e. CA would be the hostname
    Here we rely on OPenSSL -printcert output format. If it changes our output might be affected"""

    certs = cert_string.split(' ')
    hostname = ''
    for word in certs:
        if '/CN=' in word:
            if not 'CILogon' in word.split('/CN=')[1].split('\n')[0]:
                hostname = word.split('/CN=')[1].split('\n')[0]
    if hostname == '':
        raise UnexpectedBehaviourException('Unexpected behaviour by OIM retrive API. EEC certificate not found')
    return hostname


### Checking for a blank new line to seperate the certificates
### Then cheking if the hotsname is present in the certificate chunk
### If present then its the host certificate not the CA certificate
### Here we rely on OPenSSL -printcert output format. If it changes our output might be affected

def extractEEC(cert_string, hostname):
    """This function extracts the EEC certificate from the printcerts output that
    contains EEC certificate and CA certificates"""

    certs = cert_string.split('''

''')
    for line in certs:
        if hostname in line:
            return line


def read_config(itb, config_files=None):
    """This function is used to centralized the fetching of config file
    It fetches the config file and returns a dictionary of variables

    INPUT:
    itb: if True, use the [OIMData_ITB] section, otherwise use [OIMData]
    config: list of paths to config files (default: None)
    """

    config = ConfigParser.ConfigParser()
    # I don't expect user-specified config files to be used except for testing
    if not config_files:
        config_files = ['/etc/osg/pki-clients.ini',
                        'pki-clients.ini',
                        os.path.expanduser('~/.osg-pki/OSG_PKI.ini')]

    if not config.read(config_files):
        config.readfp(StringIO(DEFAULT_CONFIG))

    oim = 'OIMData'
    if itb:
        print 'Running in test mode'
        oim += '_ITB'

    return dict(config.items(oim))

class Cert(object):

    KEY_LENGTH = 2048
    PUB_EXPONENT = 0x10001

    def __init__(self, common_name, output_dir=None, altnames=None, email=None):
        """Create a certificate request (stored in the x509request attribute) and associated key file that is written to
        a temporary location (stored in the newkey attribute). It is up to the caller to write_pkey or clean up the
        temporary keys

        This function accepts the CN and final path for the key as well as optional list of subject alternative names
        and optional requestor e-mail.  """
        escaped_common_name = common_name.replace('/', '_') # Remove / from service requests for writing keys
        self.keypair = RSA.gen_key(self.KEY_LENGTH,
                                   self.PUB_EXPONENT,
                                   self.callback)

        if not output_dir:
            output_dir = os.getcwd()
        self.final_keypath = os.path.join(output_dir, escaped_common_name + '-key.pem')
        temp_key = tempfile.NamedTemporaryFile(dir=output_dir, delete=False)
        self.newkey = temp_key.name

        # The message digest shouldn't matter here since we don't use
        # PKey.sign_*() or PKey.verify_*() but there's no harm in keeping it and
        # it ensures a strong hashing algo (default is sha1) if we do decide to
        # sign things in the future
        self.pkey = EVP.PKey(md='sha256')
        self.pkey.assign_rsa(self.keypair)
        self.keypair.save_key(self.newkey, cipher=None)
        temp_key.close()

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
        if email:
            x509name.add_entry_by_txt(  # pkcs9 email address
                field='emailAddress',
                type=MBSTRING_ASC,
                entry=email,
                len=-1,
                loc=-1,
                set=0,
                )

        self.x509request.set_subject_name(x509name)

        if altnames:
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
        """Move the instance's newkey to keypath, backing up keypath to keypath.old if necessary"""
        if not keypath:
            keypath = self.final_keypath
        # Handle already existing key file...
        safe_rename(keypath)
        os.rename(self.newkey, keypath)

    def base64_csr(self):
        """Extract the base64 encoded string from the contents of a certificate signing request"""
        return format_csr(self.x509request.as_pem())
