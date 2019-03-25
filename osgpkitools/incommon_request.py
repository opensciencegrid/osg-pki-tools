#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
This script is used to submit multiple certificate requests to InCommon certificate service.
The intended user for the script is the Department Registration Authority Officer (DRAO) with SSL auto-approval and Certificate Auth enabled.

The DRAO must authenticate with  a user certificate issued by InCommon. The certificate must be configured for the DRAO in the InCommon Certificate Manager interface > Admins section. 

This script works in two modes:
1) Requesting single host certificate with -H option
2) Request multiple host certificates with hostnames stored in a file -f option

This script retrieves the certificates and output a set of files: hostname.key (private key) and hostname.pem (certificate)
"""
from __future__ import print_function

import argparse
import httplib
import socket
import sys
import os
import time
import traceback
import json
import ConfigParser

import logging
logger = logging.getLogger('incommon_request')
logging.basicConfig()

from StringIO import StringIO
from ssl import SSLError
from optparse import OptionParser, OptionGroup

import utils
import cert_utils
from ExceptionDefinitions import *
from rest_client import InCommonApiClient

MAX_RETRY_RETRIEVAL = 20
WAIT_RETRIEVAL= 5
WAIT_APPROVAL = 30

CONFIG_TEXT = """[InCommon]
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

def parse_cli():
    """This function parses all the arguments, validates them and then stores them
    in a dictionary that is used throughout the script."""
    
    usage = \
    '''%(prog)s [--debug] -u username -k pkey -c cert \\
           (-H hostname | -F hostfile) [-a altnames] [-d write_directory]
       %(prog)s [--debug] -u username -k pkey -c cert -t
       %(prog)s -h
       %(prog)s --version'''
 
    parser = argparse.ArgumentParser(add_help=False, usage=usage, 
                                     description='Request and retrieve certificates from the  InCommon IGTF server CA.')

    required = parser.add_argument_group('Required', 'Specify only one of -H/--hostname and -F/--hostfile')
    hosts = required.add_mutually_exclusive_group()
    hosts.add_argument('-H', '--hostname', action='store', dest='hostname',
                        help='The hostname (FQDN) to request. If specified, -F/--hostfile will be ignored')
    hosts.add_argument('-F', '--hostfile', action=FilePathAction, dest='hostfile',
                       help='File containing list of hostnames (FQDN), one per line, to request. Space separated '
                       'subject alternative names (SANs) may be specified on the same line as each hostname.')

    required.add_argument('-u', '--username', action='store', required=True, dest='login',
                          help="Specify requestor's InCommon username/login")

    required.add_argument('-c', '--cert', action=FilePathAction, required=True, dest='usercert',
                          help="Specify requestor's user certificate (PEM Format)")
    
    required.add_argument('-k', '--pkey', action=FilePathAction, required=True, dest='userprivkey',
                          help="Specify requestor's private key (PEM Format)")

    optional = parser.add_argument_group("Optional")
    optional.add_argument('-h', '--help', action='help',
                          help='show this help message and exit')
    optional.add_argument('-a', '--altname', action='append', dest='altnames', default=[],
                          help='Specify the SAN for the requested certificate (only works with -H/--hostname). '
                          'May be specified more than once for additional SANs.')
    optional.add_argument('-o', '--outputdir', action='store', dest='write_directory', default='.',
                          help="The directory to write the host certificate(s) and key(s)")
    optional.add_argument('-d', '--debug', action='store_true', dest='debug', default=False,
                          help="Write debug output to stdout")
    optional.add_argument('-t', '--test', action='store_true', dest='test', default=False,
                              help='Testing mode: test connection to InCommon API but does not request certificates. '
                              'Useful to test authentication credentials, optional arguments are ignored.')
    optional.add_argument('-v', '--version', action='version', version=utils.VERSION_NUMBER)

    parsed_args = parser.parse_args()

    # We can't add altnames to the mutually exclusive 'hosts' group since it's not a required opt
    if parsed_args.hostfile and parsed_args.altnames:
        parsed_args.altnames = []
        print("-a/--altname option ignored with -F/--hostfile", file=sys.stderr)
    
    if parsed_args.debug:
        # this sets the root debug level
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug('Debug mode enabled')
    
    # (-H/--hostname | -F/--hostfile) are mutually exclusive but not required so testing mode can be enabled with optional param -t/--test 
    if not parsed_args.test and not parsed_args.hostname and not parsed_args.hostfile:
        parser.print_usage()
        raise InsufficientArgumentException("InsufficientArgumentException: " + \
                                            "Please provide -H/--hostname and -F/--hostfile for normal mode. " + \
                                            "For testing mode, use -t/--test")

    return parsed_args


class FilePathAction(argparse.Action):
    """Action for validating if the file exists and there are read permissions
    """
    def __call__(self, parser, namespace, values, option_string=None):
        values = os.path.expanduser(values)

        if not os.path.exists(values):
            raise IOError("Unable to locate the file at: %s" % values)
        
        try:
            open(values, 'r')
            setattr(namespace, self.dest, values)
        except IOError:
            raise IOError("Unable to read the file at: %s" % values)
   

def build_headers(config):
    """"This function build the headers for the HTTP request.
        Returns headers for the HTTP request
    """
    headers = {
            "Content-type": str(config['content_type']), 
            "login": str(args.login), 
            "customerUri": str(config['customeruri']) 
    }

    return headers


def test_incommon_connection(config, restclient):
    """This function tests the connection to InCommon API
       and the credentials for authentication: cert and key.
       Performs a call to the listing SSL types endpoint. 
       Successful if response is HTTP 200 OK
    """
    # Build headers.
    headers = build_headers(config)
    response = None
    
    response = restclient.get_request(config['listingurl'], headers)
    response_text = response.read()
    logger.debug('response text: ' + str(response_text))
    try:
        if response.status == 200:
            print("Connection successful to InCommon API") 
        else:
            # InCommon API HTTP Error codes and messages are not consistent with documentation.
            # {Unknown user}
            print("Connection failure to InCommon API. Check your authentication credentials.")
    except httplib.HTTPException as exc:
        print("HTTPS Connection error. Details: \n %s" % str(exc))
        

def submit_request(config, restclient, hostname, cert_csr, sans=None):
    """This function submits an enrollment request for a certificate
       If successful returns a self-enrollment certificate Id = sslId
    """
    # Build and update headers for the restclient 
    headers = build_headers(config)

    response = None
    response_data = None

    cert_type = config['igtfservercert']
    
    if sans:
        cert_type = config['igtfmultidomain']
    
    payload = dict(
        csr=cert_csr,
        orgId=config['department'],
        certType=cert_type,
        numberServers=0,
        serverType=config['servertype'],
        term=config['term'],
        comments="Certificate request for " + hostname
    )
   
    if sans:
        payload.update(subjAltNames=sans)
    
    try:
        response = restclient.post_request(config['enrollurl'], headers, payload)
        
        if response.status == 200:
            response_text = response.read()
            logger.debug('response text: ' + str(response_text))
            response_data = json.loads(response_text)
            response_data = response_data['sslId']
        else:
            raise AuthenticationFailureException(response.status, "Connection failure to InCommon API. Check your authentication credentials.")
    except httplib.HTTPException as exc:
        raise
    
    return response_data
    
def retrieve_cert(config, sslcontext, sslId):
    """This function retrieves a certificate given a self-enrollment certificate Id = sslId
    """
    
    # Build and update headers for the restclient. Headers will be reused for all requests
    headers = build_headers(config)

    response = None
    response_data = None    

    retry_count = MAX_RETRY_RETRIEVAL
    retrieve_url = config['retrieveurl'] + str(sslId) + config['certx509co']
    
    for _ in range(retry_count):
        try:
            # If the HTTPSConnection is reused 
            restclient = InCommonApiClient(config['apiurl'], sslcontext)
            response = restclient.get_request(retrieve_url, headers)
            # InCommon API responds with HTTP 400 Bad Request when the certificate is still being procesed
            # "code": 0, "description": "Being processed by Sectigo"
            # Triggers the BadStatusLine exception avoiding to reuse the HTTPSConnection
            response_text = response.read()
            logger.debug('response text: ' + str(response_text))
            # HTTP 200 OK brings the certificate in the response, HTTPSConnection will be closed before exiting the loop 
            if response.status == 200:
                print("    - Certificate request is approved. Downloading certificate now.")
                response_data = response_text
                restclient.close_connection()
                break
        except httplib.BadStatusLine as exc:
            # BadStatusLine is raised as the server responded with a HTTP status code that we don't understand.
            pass
        except httplib.HTTPException as exc:
            raise
        print("    - Certificate request is pending approval...")    
        print("    - Waiting for %s seconds before retrying certificate retrieval" % WAIT_RETRIEVAL )
        # Closing the connection before going to sleep
        restclient.close_connection()
        time.sleep(WAIT_RETRIEVAL)
    
    return response_data
           
def main():
    """The entrypoint for osg-incommon-cert-request
    """
    global args
    try:
        args = parse_cli()
   
        config_parser = ConfigParser.ConfigParser()
        config_parser.readfp(StringIO(CONFIG_TEXT))
        CONFIG = dict(config_parser.items('InCommon'))

        utils.check_permissions(args.write_directory)
        
        if args.test:
            print("Beginning testing mode: ignoring optional parameters.")

        # Creating SSLContext with cert and key provided
        # usercert and userprivkey are already validated by utils.findusercred
        ssl_context = cert_utils.get_ssl_context(usercert=args.usercert, userkey=args.userprivkey)
        
        restclient = InCommonApiClient(CONFIG['apiurl'], ssl_context)

        if args.test:
            test_incommon_connection(CONFIG, restclient)
            restclient.close_connection()
            sys.exit(0)

        print("Beginning certificate request")
        print("="*60)
        
        #Create tuple(s) either with a single hostname and altnames or with a set of hostnames and altnames from the hostfile
        if args.hostname:
            hosts = [tuple([args.hostname.strip()] + args.altnames)]
        else:
            with open(args.hostfile, 'rb') as hosts_file:
                host_lines = hosts_file.readlines()
            hosts = [tuple(line.split()) for line in host_lines if line.strip()]
        
        requests = list()
        csrs = list()

        print("The following Common Name (CN) and Subject Alternative Names (SANS) have been specified: ")
        # Building the lists with certificates --> utils.Csr(object) 
        for host in set(hosts):
            common_name = host[0]
            sans = host[1:]
            
            print("CN: %s, SANS: %s" % (common_name, sans))
            csr_obj = cert_utils.Csr(common_name, output_dir=args.write_directory, altnames=sans)
            
            logger.debug(csr_obj.x509request.as_text())
            csrs.append(csr_obj)

        print("="*60)

        for csr in csrs:
            subj = str(csr.x509request.get_subject())
            print("Requesting certificate for %s: " % subj)
            response_request = submit_request(CONFIG, restclient, subj, csr.base64_csr(), sans=csr.altnames)
            
            # response_request stores the sslId for the certificate request
            if response_request:
                requests.append(tuple([response_request, subj]))
                print("Request successful. Writing key file at: %s" % csr.keypath)
                csr.write_pkey()
            else:
                print("Request failed for %s" % subj)
            
            print("-"*60)
        
        # Closing the restclient connection before going idle waiting for approval
        restclient.close_connection()
        
        print("%s certificate(s) was(were) requested successfully." % len(requests))
        print("Waiting %s seconds for requests approval..." % WAIT_APPROVAL)
        time.sleep(WAIT_APPROVAL) 
        
        print("\nStarting certificate retrieval")
        print("="*60)
        # Certificate retrieval has to retry until it gets the certificate
        # A restclient (InCommonApiClient) needs to be created for each retrieval attempt
        for request in requests:
            subj = request[1]
            print("Retrieving certificate for %s: " % subj)
            response_retrieve = retrieve_cert(CONFIG, ssl_context, request[0])

            if response_retrieve is not None:
                cert_path = os.path.join(args.write_directory, subj.split("=")[1] + '-cert.pem')
                print("Retrieval successful. Writing certificate file at: %s" % cert_path)
                utils.safe_rename(cert_path)
                utils.atomic_write(cert_path, response_retrieve)
                os.chmod(cert_path, 0644)
            else:
                print("Retrieval failure for %" % subj)
                print("The certificate can be retrieved directly from the InCommon Cert Manager interface.")
                print("CN %s, Self-enrollment Certificate ID (sslId): %s" % (subj, request[0]))
            
            print("-"*60)

    except SystemExit:
        raise
    except ValueError as exc:
        sys.exit(exc)
    except IOError as exc:
        print("Error: more details below.")
        utils.print_exception_message(exc)
        sys.exit(1)
    except KeyboardInterrupt as exc:
        utils.print_exception_message(exc)
        sys.exit('''Interrupted by user\n''')
    except KeyError as exc:
        print('Key %s not found' % exc)
        sys.exit(1)
    except FileWriteException as exc:
        print(str(exc))
        sys.exit(1)
    except FileNotFoundException as exc:
        print(str(exc) + ':' + exc.filename)
        sys.exit(1)
    except SSLError as exc:
        utils.print_exception_message(exc)
        sys.exit('Please check for valid certificate.\n')
    except (BadPassphraseException, AttributeError, EnvironmentError, ValueError, EOFError, SSLError) as exc:
        print(str(exc))
        sys.exit(1)
    except InsufficientArgumentException as exc:
        print("Insufficient arguments provided. More details below: ")
        utils.print_exception_message(exc)
        sys.stderr.write("Usage: incommon-cert-request -h for help \n")
        sys.exit(1)
    except AuthenticationFailureException as exc:
        utils.print_exception_message(exc)
        sys.exit('Check your authentication credentials.\n')
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    sys.exit(0)
