#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# vim: ts=4 sw=4 nowrap
#

import M2Crypto
import base64
import ConfigParser
import os
import time
import sys
import textwrap
import simplejson

from ExceptionDefinitions import *

# These flags are for the purpose of passing to the M2Crypto calls and are used later in the script

MBSTRING_FLAG = 0x1000
MBSTRING_ASC = MBSTRING_FLAG | 1
MBSTRING_BMP = MBSTRING_FLAG | 2


def check_response_500(response):
    """ This functions handles the 500 error response from the server"""

    if response.status == 500:
        raise Exception_500response(response.status, reponse.reason)

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
    """This function wraps up tht output to 80 characters. Accepts string and print the wrapped output"""

    list_string = textwrap.wrap(string)
    for line in list_string:
        print line
    return


def get_request_count(filename):
    '''Returns the number of hostname requested in the file supplied as -f furing bulk certificate request'''

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


### We take the whole certificate data as a stirng input
### Checking for /CN= in every line and extracting the term after that if not Digicert i.e. CA would be the hostname
### Here we rely on OPenSSL -printcert output format. If it changes our output might be affected

def extractHostname(certString):
    """Extracts hostname from the string of certifcate file
....We take the whole certificate data as a stirng input
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
    certArray = certString.split('''

''')
    for certArrayString in certArray:
        if hostname in certArrayString:
            return certArrayString


def CreateOIMConfig(isITB, **OIMConfig):
    Config = ConfigParser.ConfigParser()
    if os.path.exists(str(os.environ['HOME']) + '/.osg-pki/OSG_PKI.ini'
                      ):
        print 'Overriding INI file with %s/.osg-pki/OSG_PKI.ini' \
            % str(os.environ['HOME'])
        Config.read(str(os.environ['HOME']) + '/.osg-pki/OSG_PKI.ini')
    elif os.path.exists('pki-clients.ini'):
        Config.read('pki-clients.ini')
    elif os.path.exists('/etc/pki-clients.ini'):
        Config.read('/etc/pki-clients.ini')
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

        self.KeyPair = M2Crypto.RSA.gen_key(self.RsaKey['KeyLength'],
                self.RsaKey['PubExponent'],
                self.RsaKey['keygen_callback'])
        PubKey = M2Crypto.RSA.new_pub_key(self.KeyPair.pub())
        self.KeyPair.save_key(filename, cipher=None)
        self.PKey = M2Crypto.EVP.PKey(md='sha1')
        self.PKey.assign_rsa(self.KeyPair)

    def CreateX509Request(self, **config_items):
        """This function accepts a dctionary that contains information regarding the CSR.
........It creates a CSR and returns it to the calling script."""

        #
        # X509 REQUEST
        #

        self.X509Request = M2Crypto.X509.Request()

        #
        # subject
        #

        X509Name = M2Crypto.X509.X509_Name()

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

        #
        # publickey
        #

        self.X509Request.set_pubkey(pkey=self.PKey)
        self.X509Request.sign(pkey=self.PKey, md='sha1')
        return self.X509Request


