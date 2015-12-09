#!/usr/bin/python

from M2Crypto import SSL, m2, RSA, EVP, X509
import base64
import ConfigParser
import os
import time
import sys
import textwrap
import simplejson
import traceback
import getpass

from ExceptionDefinitions import *

# These flags are for the purpose of passing to the M2Crypto calls and are used later in the script

MBSTRING_FLAG = 0x1000
MBSTRING_ASC = MBSTRING_FLAG | 1
MBSTRING_BMP = MBSTRING_FLAG | 2

# The variable for storing version number for the scripts
Version_Number = "1.2.12"


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
    first = True
    count = 0
    pass_str = 'Please enter the pass phrase for'
    while(True):
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
        except Exception, e:
            if 'sslv3 alert bad certificate' in e:
                raise BadCertificateException('Error connecting to server: %s.\n\
                                          Your certificate is not trusted by the server'
                 % e)
            elif 'handshake failure' in e:
                raise HandshakeFailureException('Failure: %s.\nPlease check for valid certificate/key pairs.'
                 % e)
            first = False
            count = count + 1
            pass_str = 'Incorrect password. Please enter the password again for'
            if count > 1:
                raise BadPassphraseException('Incorrect passphrase. Attempt failed twice. Exiting script'
                        )
                break
    return ssl_context


def print_exception_message(e):
    """Checks if the str representation of the exception is empty or not
    if empty, it prints an generic error message stating the type of exception
    and traceback.
    """

    if(str(e) != ""):
        charlimit_textwrap("Got an exception %s" % e.__class__.__name__)
        charlimit_textwrap(e)
        charlimit_textwrap('Please report the bug to goc@opensciencegrid.org.')

    else:
        handle_empty_exceptions(e)

def print_uncaught_exception():
    """This function prints the stack trace of a failure to aid
    debugging"""
    print traceback.format_exc()

def handle_empty_exceptions(e):
    """The method handles all empty exceptions and displays a meaningful message and
    traceback for such exceptions."""
    
    print traceback.format_exc()
    charlimit_textwrap('Encountered exception of type %s' % e.__class__.__name__)
    charlimit_textwrap('Please report the bug to goc@opensciencegrid.org.')

def version_info():
    """ Print the version number and exit"""
    print "OSG CLI Scripts Version :", Version_Number

def check_permissions(path):
    """The function checks for write permissions for the given path to verify if the user has write permissions
    """
    if(os.access(path, os.W_OK)):
        return
    else:
        raise FileWriteException("User does not have appropriate permissions for writing to current directory.")

def find_existing_file_count(filename):
    '''Check if filename and revisions of the filename exists. If so, increment the revision number and return
    the latest revision filename'''
    temp_name = filename.split(".")[-2]
    trimmed_name = temp_name
    version_count = 0
    if(os.path.exists(filename)):
        while(os.path.exists(temp_name + '.pem')):
            if (version_count == 0):
                temp_name = temp_name +'-'+str(version_count)
            else:
                temp_name = trimmed_name
                temp_name = temp_name + '-' + str(version_count)
            version_count = version_count + 1

    if (version_count > 0):
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
        charlimit_textwrap('The request has failed for the following reason:\n%s'
                            % simplejson.loads(data)['detail'
                           ].split('--')[1].lstrip())
    except IndexError, e:
        charlimit_textwrap('The request has failed for the following reason:\n%s'
                            % simplejson.loads(data)['detail'].lstrip())
        charlimit_textwrap('Status : %s '
                           % simplejson.loads(data)['status'])
    sys.exit(1)


def check_for_pending(data, iterations, **arguments):
    """ This function is a centralized location to print the in process output indication"""

    time.sleep(5)
    iterations = iterations + 1
    if iterations % 6 == 0:
        print '.',
        sys.stdout.flush()
    check_timeout(iterations, arguments['timeout'])
    return iterations


def check_timeout(iterations, timeout):
    """This function checks for a timeout. If timeout has occurred it raises a TIMEOUT EXCEPTION"""

    if iterations > timeout * 12:
        raise TimeoutException(timeout)
    else:
        return


def charlimit_textwrap(string):
    """This function wraps up the output to 80 characters. Accepts string and print the wrapped output"""

    list_string = textwrap.wrap(str(string))
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

def extractHostname(certString):
    """Extracts hostname from the string of certifcate file
....We take the whole certificate data as a string input
....Checking for /CN= in every line and extracting the term after that if not Digicert i.e. CA would be the hostname
....Here we rely on OPenSSL -printcert output format. If it changes our output might be affected"""

    certArray = certString.split(' ')
    hostname = ''
    for subStr in certArray:
        if '/CN=' in subStr:
            if not 'DigiCert' in subStr.split('/CN=')[1].split('\n')[0]:
                hostname = subStr.split('/CN=')[1].split('\n')[0]
    if hostname == '':
        raise UnexpectedBehaviourException('Unexpected behaviour by OIM retrive API. EEC certificate not found'
                )
    return hostname


### Checking for a blank new line to seperate the certificates
### Then cheking if the hotsname is present in the certificate chunk
### If present then its the host certificate not the CA certificate
### Here we rely on OPenSSL -printcert output format. If it changes our output might be affected

def extractEEC(certString, hostname):
    """This function extracts the EEC certificate from the printcerts output that
    contains EEC certificate and CA certificates"""

    certArray = certString.split('''

''')
    for certArrayString in certArray:
        if hostname in certArrayString:
            return certArrayString


def CreateOIMConfig(isITB, **OIMConfig):
    """This function is used to centralized the fetching of config file
    It fetches the config file and updates the dictionary of variables"""

    Config = ConfigParser.ConfigParser()
    if os.path.exists(str(os.environ['HOME']) + '/.osg-pki/OSG_PKI.ini'):
        print 'Overriding INI file with %s/.osg-pki/OSG_PKI.ini' % str(os.environ['HOME'])
        Config.read(str(os.environ['HOME']) + '/.osg-pki/OSG_PKI.ini')
    elif os.path.exists('pki-clients.ini'):
        Config.read('pki-clients.ini')

    ### Fix for pki-clients.ini not found in /etc/osg/
    elif os.path.exists('/etc/osg/pki-clients.ini'):
        Config.read('/etc/osg/pki-clients.ini')
        
    else:
        raise FileNotFoundException('pki-clients.ini',
                                    'Could not locate the file')
    if isITB:
        print 'Running in test mode'
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
    OIMConfig.update({'renewurl': Config.get(OIM, 'renewurl')})
    OIMConfig.update({'userreturl': Config.get(OIM, 'userreturl')})
    OIMConfig.update({'userrevurl': Config.get(OIM, 'userrevurl')})
    OIMConfig.update({'issurl': Config.get(OIM, 'issurl')})
    OIMConfig.update({'quotaurl': Config.get(OIM, 'quotaurl')})
    OIMConfig.update({'content_type': Config.get(OIM, 'content_type')})
    return OIMConfig


class Cert:

    def __init__(self):
        self.RsaKey = {'KeyLength': 2048, 'PubExponent': 0x10001,
                       'keygen_callback': self.callback}  # -> 65537

        self.KeyPair = None
        self.PKey = None

        self.X509Request = None
        self.X509Certificate = None

    def callback(self, *args):
        return None

    def CreatePKey(self, filename):
        """This function accepts the filename of the key file to write to.
........It write the private key to the specified file name without ciphering it."""

        self.KeyPair = RSA.gen_key(self.RsaKey['KeyLength'],
                self.RsaKey['PubExponent'],
                self.RsaKey['keygen_callback'])
        PubKey = RSA.new_pub_key(self.KeyPair.pub())
        self.KeyPair.save_key(filename, cipher=None)
        self.PKey = EVP.PKey(md='sha1')
        self.PKey.assign_rsa(self.KeyPair)
        return


    def CreateX509Request(self, **config_items):
        """This function accepts a dctionary that contains information regarding the CSR.
........It creates a CSR and returns it to the calling script."""

        #
        # X509 REQUEST
        #

        self.X509Request = X509.Request()

        #
        # subject
        #

        X509Name = X509.X509_Name()

        X509Name.add_entry_by_txt(  # common name
            field='CN',
            type=MBSTRING_ASC,
            entry=config_items['CN'],
            len=-1,
            loc=-1,
            set=0,
            )
        if config_items.has_key('emailAddress'):
            X509Name.add_entry_by_txt(  # pkcs9 email address
                field='emailAddress',
                type=MBSTRING_ASC,
                entry=config_items['emailAddress'],
                len=-1,
                loc=-1,
                set=0,
                )

        self.X509Request.set_subject_name(X509Name)

        alt_names = config_items.get('alt_names')
        if alt_names:
            extension_stack = X509.X509_Extension_Stack()
            extension = X509.new_extension('subjectAltName',
                                           ", ".join(['DNS:%s' % name for name in alt_names]))
            extension.set_critical(1)
            extension_stack.push(extension)
            self.X509Request.add_extensions(extension_stack)

        #
        # publickey
        #

        self.X509Request.set_pubkey(pkey=self.PKey)
        self.X509Request.set_version(0)
        self.X509Request.sign(pkey=self.PKey, md='sha1')
        return self.X509Request

