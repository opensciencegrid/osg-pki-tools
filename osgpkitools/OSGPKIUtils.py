#!/usr/bin/python

from M2Crypto import SSL, m2, RSA, EVP, X509
import ConfigParser
import os
import re
import time
import sys
import textwrap
import simplejson
import signal
import traceback
import getpass

from ExceptionDefinitions import *

# These flags are for the purpose of passing to the M2Crypto calls and are used later in the script

MBSTRING_FLAG = 0x1000
MBSTRING_ASC = MBSTRING_FLAG | 1
MBSTRING_BMP = MBSTRING_FLAG | 2

# The variable for storing version number for the scripts
Version_Number = "1.2.17"


def get_ssl_context(**arguments):
    """ This function sets the ssl context by accepting the passphrase
    and validating it for user private key and his certificate
    INPUT :
    arguments - A dict containing
    userprivkey - Filename for private key of user.
    usercert    - Filename for user certificate.

    OUTPUT :
    ssl_context - ssl context for the HTTPS connection.

    """
    count = 0
    pass_str = 'Please enter the pass phrase for'
    while True:
        try:
            def prompt_for_password(verify):
                return getpass.getpass(pass_str+" '%s':"
                                       % arguments['userprivkey'])

            ssl_context = SSL.Context()
            ssl_context.set_options(m2.SSL_OP_NO_SSLv2 | m2.SSL_OP_NO_SSLv3)
            ssl_context.load_cert_chain(arguments['usercert'],
                                        arguments['userprivkey'],
                                        callback=prompt_for_password)
            break
        except Exception, exc:
            if 'sslv3 alert bad certificate' in exc:
                raise BadCertificateException('Error connecting to server: %s. \n' + \
                                              'Your certificate is not trusted by the server'
                                              % exc)
            elif 'handshake failure' in exc:
                raise HandshakeFailureException('Failure: %s.\nPlease check for valid certificate/key pairs.'
                                                % exc)
            count = count + 1
            pass_str = 'Incorrect password. Please enter the password again for'
            if count > 1:
                raise BadPassphraseException('Incorrect passphrase. Attempt failed twice. Exiting script')
    return ssl_context


def print_exception_message(exc):
    """Checks if the str representation of the exception is empty or not
    if empty, it prints an generic error message stating the type of exception
    and traceback.
    """

    if str(exc) != "":
        charlimit_textwrap("Got an exception %s" % exc.__class__.__name__)
        charlimit_textwrap(exc)
        charlimit_textwrap('Please report the bug to goc@opensciencegrid.org.')
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
    charlimit_textwrap('Please report the bug to goc@opensciencegrid.org.')

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
              simplejson.loads(data)['detail'].split('--')[1].lstrip()
    except IndexError:
        msg = 'The request has failed for the following reason: %s' % simplejson.loads(data)['detail'].lstrip() + \
              'Status : %s ' % simplejson.loads(data)['status']

    # Print a helpful error message if OIM responds that the user needs to
    # provide a VO in their request. We cannot handle this in the arg parsing
    # because not all domains require VO information (SOFTWARE-2292)
    if re.search(r'Couldn\'t find GridAdmin group under specified VO', msg):
        msg = "Failed to request certificate due to missing VO information. Did you forget to specify the -v/--vo option?"
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


def get_request_count(filename):
    '''Returns the number of hostname requested in the file supplied as -f during bulk certificate request'''

    hostfile = open(filename, 'rb')
    name_set = set()
    count = 0
    for line in hostfile.readlines():
        line = line.strip(' \n')
        if not line in name_set:
            name_set.add(line)
            count += 1
    hostfile.close()
    return count


### We take the whole certificate data as a string input
### Checking for /CN= in every line and extracting the term after that if not Digicert i.e. CA would be the hostname
### Here we rely on OPenSSL -printcert output format. If it changes our output might be affected

def extractHostname(cert_string):
    """Extracts hostname from the string of certifcate file
    We take the whole certificate data as a string input
    Checking for /CN= in every line and extracting the term after that if not Digicert i.e. CA would be the hostname
    Here we rely on OPenSSL -printcert output format. If it changes our output might be affected"""

    certs = cert_string.split(' ')
    hostname = ''
    for word in certs:
        if '/CN=' in word:
            if not 'DigiCert' in word.split('/CN=')[1].split('\n')[0]:
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


def CreateOIMConfig(isITB, **OIMConfig):
    """This function is used to centralized the fetching of config file
    It fetches the config file and updates the dictionary of variables"""

    config = ConfigParser.ConfigParser()
    if os.path.exists(str(os.environ['HOME']) + '/.osg-pki/OSG_PKI.ini'):
        print 'Overriding INI file with %s/.osg-pki/OSG_PKI.ini' % str(os.environ['HOME'])
        config.read(str(os.environ['HOME']) + '/.osg-pki/OSG_PKI.ini')
    elif os.path.exists('pki-clients.ini'):
        config.read('pki-clients.ini')

    ### Fix for pki-clients.ini not found in /etc/osg/
    elif os.path.exists('/etc/osg/pki-clients.ini'):
        config.read('/etc/osg/pki-clients.ini')

    else:
        raise FileNotFoundException('pki-clients.ini',
                                    'Could not locate the file')
    if isITB:
        print 'Running in test mode'
        oim = 'OIMData_ITB'
        OIMConfig.update({'host': 'oim-itb.grid.iu.edu:80'})
        OIMConfig.update({'hostsec': 'oim-itb.grid.iu.edu:443'})
    else:
        oim = 'OIMData'
        OIMConfig.update({'host': 'oim.grid.iu.edu:80'})
        OIMConfig.update({'hostsec': 'oim.grid.iu.edu:443'})
    OIMConfig.update({'requrl': config.get(oim, 'requrl')})
    OIMConfig.update({'appurl': config.get(oim, 'appurl')})
    OIMConfig.update({'revurl': config.get(oim, 'revurl')})
    OIMConfig.update({'canurl': config.get(oim, 'canurl')})
    OIMConfig.update({'returl': config.get(oim, 'returl')})
    OIMConfig.update({'renewurl': config.get(oim, 'renewurl')})
    OIMConfig.update({'userreturl': config.get(oim, 'userreturl')})
    OIMConfig.update({'userrevurl': config.get(oim, 'userrevurl')})
    OIMConfig.update({'issurl': config.get(oim, 'issurl')})
    OIMConfig.update({'quotaurl': config.get(oim, 'quotaurl')})
    OIMConfig.update({'content_type': config.get(oim, 'content_type')})
    return OIMConfig


class Cert:

    def __init__(self):
        self.rsakey = {'KeyLength': 2048, 'PubExponent': 0x10001,
                       'keygen_callback': self.callback}  # -> 65537

        self.keypair = None
        self.pkey = None

        self.x509request = None
        self.x509certificate = None

    def callback(self, *args):
        return None

    def CreatePKey(self, filename):
        """This function accepts the filename of the key file to write to.
........It write the private key to the specified file name without ciphering it."""

        self.keypair = RSA.gen_key(self.rsakey['KeyLength'],
                                   self.rsakey['PubExponent'],
                                   self.rsakey['keygen_callback'])
        RSA.new_pub_key(self.keypair.pub())
        self.keypair.save_key(filename, cipher=None)
        self.pkey = EVP.PKey(md='sha1')
        self.pkey.assign_rsa(self.keypair)


    def CreateX509Request(self, **config_items):
        """This function accepts a dctionary that contains information regarding the CSR.
........It creates a CSR and returns it to the calling script."""

        #
        # X509 REQUEST
        #

        self.x509request = X509.Request()

        #
        # subject
        #

        x509name = X509.X509_Name()

        x509name.add_entry_by_txt(  # common name
            field='CN',
            type=MBSTRING_ASC,
            entry=config_items['CN'],
            len=-1,
            loc=-1,
            set=0,
            )
        if config_items.has_key('emailAddress'):
            x509name.add_entry_by_txt(  # pkcs9 email address
                field='emailAddress',
                type=MBSTRING_ASC,
                entry=config_items['emailAddress'],
                len=-1,
                loc=-1,
                set=0,
                )

        self.x509request.set_subject_name(x509name)

        alt_names = config_items.get('alt_names')
        if alt_names:
            extension_stack = X509.X509_Extension_Stack()
            extension = X509.new_extension('subjectAltName',
                                           ", ".join(['DNS:%s' % name for name in alt_names]))
            extension.set_critical(1)
            extension_stack.push(extension)
            self.x509request.add_extensions(extension_stack)

        #
        # publickey
        #

        self.x509request.set_pubkey(pkey=self.pkey)
        self.x509request.set_version(0)
        self.x509request.sign(pkey=self.pkey, md='sha1')
        return self.x509request

