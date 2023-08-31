#!/usr/bin/python3
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


prog = "osg-incommon-cert-request"
args = None
import argparse
import http.client
import socket
import sys
import os
import time
import traceback
import json
import configparser

import logging
logger = logging.getLogger('incommon_request')
logging.basicConfig()

from io import StringIO
from ssl import SSLError

from . import utils
from . import cert_utils
from .ExceptionDefinitions import *
from .rest_client import InCommonApiClient

MAX_RETRY_RETRIEVAL = 40
WAIT_RETRIEVAL= 10
WAIT_APPROVAL = 30


def parse_cli():
    """This function parses all the arguments, validates them and then stores them
    in a dictionary that is used throughout the script."""
    
    usage = \
    '''%(prog)s [--debug] -u username -k pkey -c cert \\
           (-H hostname | -F hostfile) [-a altnames] [-d write_directory] \\
           [-O org,dept]
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
    optional.add_argument('-C', '--config', action='store', dest='config_file', default='/etc/osg/pki/ca-issuer.conf'
                          'Path to configuration file')
    optional.add_argument('-d', '--directory', action='store', dest='write_directory', default='.',
                          help="The directory to write the host certificate(s) and key(s)")
    optional.add_argument('-O', '--orgcode', action='store', dest='orgcode', default='9697,9732', metavar='ORG,DEPT',
                          help='Organization and Department codes for the InCommon Certificate Service. Defaults are Fermilab\'s codes.')
    optional.add_argument('-l', '--key-length', action='store', default=cert_utils.Csr.KEY_LENGTH,
                          type=int, help='The key size to generate')
    optional.add_argument('--debug', action='store_true', dest='debug', default=False,
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
        parser.error('argument -H/--hostname or -F/--hostfile is required.')

    return parsed_args


class FilePathAction(argparse.Action):
    """Action for validating if the file exists and there are read permissions
    """
    def __call__(self, parser, namespace, values, option_string=None):
        values = os.path.expanduser(values)

        if not os.path.exists(values):
            raise IOError(f"Unable to locate the file at: {values}")
        
        try:
            open(values, 'r')
            setattr(namespace, self.dest, values)
        except IOError:
            raise IOError(f"Unable to read the file at: {values}")
   

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
            print(prog + ": Connection successful to InCommon API") 
        else:
            # InCommon API HTTP Error codes and messages are not consistent with documentation.
            print(prog + ": Connection failure to InCommon API")

            if response.status == 401:
                print("Check your authentication credentials")

            print("HTTP " + str(response.status) + " " + str(response.reason))
    except http.client.HTTPException as exc:
        print(prog + f": HTTPS Connection error. Details: \n {str(exc)}")


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
        elif response.status == 401:
            raise AuthenticationFailureException(response.status, "Connection failure to InCommon API. Check your authentication credentials.")
        else:
            print(prog + ": Connection failure to InCommon API. HTTP " + str(response.status) + " " + str(response.reason))
            raise http.client.HTTPException()
    except http.client.HTTPException as exc:
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
        except http.client.BadStatusLine as exc:
            # BadStatusLine is raised as the server responded with a HTTP status code that we don't understand.
            pass
        except http.client.HTTPException as exc:
            raise
        print("    - Certificate request is pending approval...")    
        print(f"    - Waiting for {WAIT_RETRIEVAL} seconds before retrying certificate retrieval" )
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
   
        config_parser = configparser.ConfigParser()
        config_parser.read(args.config_file)
        CONFIG = dict(config_parser.items('InCommon'))
        
        if args.orgcode:
            codes = [code.strip() for code in args.orgcode.split(',')]
            CONFIG['organization'] = codes[0]
            CONFIG['department'] = codes[1]
        
        print(f"Using organization code of {CONFIG['organization']} and department code of {CONFIG['department']}")

        utils.check_permissions(args.write_directory)
         
        if args.test:
            print("Beginning testing mode: ignoring optional parameters.")
            print("="*60)

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
            with open(args.hostfile) as hosts_file:
                host_lines = hosts_file.readlines()
            hosts = [tuple(line.split()) for line in host_lines if line.strip()]
        
        requests = list()
        csrs = list()

        print("The following Common Name (CN) and Subject Alternative Names (SANS) have been specified: ")
        # Building the lists with certificates --> utils.Csr(object) 
        for host in set(hosts):
            common_name = host[0]
            sans = host[1:]
            
            print(f"CN: {common_name}, SANS: {sans}")
            csr_obj = cert_utils.Csr(common_name,
                                     output_dir=args.write_directory,
                                     altnames=sans, key_length=args.key_length)
            
            logger.debug(csr_obj.x509request.as_text())
            csrs.append(csr_obj)

        print("="*60)

        for csr in csrs:
            subj = str(csr.x509request.get_subject())
            print(f"Requesting certificate for {subj}: ")
            response_request = submit_request(CONFIG, restclient, subj, csr.base64_csr(), sans=csr.altnames)
            
            # response_request stores the sslId for the certificate request
            if response_request:
                requests.append(tuple([response_request, subj]))
                print(f"Request successful. Writing key file at: {csr.keypath}")
                csr.write_pkey()
            else:
                print(f"Request failed for {subj}")
            
            print("-"*60)
        
        # Closing the restclient connection before going idle waiting for approval
        restclient.close_connection()
        
        print(f"{len(requests)} certificate(s) was(were) requested successfully")
        print(f"Waiting {WAIT_APPROVAL} seconds for requests approval...")
        time.sleep(WAIT_APPROVAL) 
        
        print("\nStarting certificate retrieval")
        print("="*60)
        # Certificate retrieval has to retry until it gets the certificate
        # A restclient (InCommonApiClient) needs to be created for each retrieval attempt
        for request in requests:
            subj = request[1]
            print(f"Retrieving certificate for {subj}: ")
            response_retrieve = retrieve_cert(CONFIG, ssl_context, request[0])

            if response_retrieve is not None:
                cert_path = os.path.join(args.write_directory, subj.split("=")[1] + '-cert.pem')
                print(f"Retrieval successful. Writing certificate file at: {cert_path}")
                utils.safe_rename(cert_path)
                utils.atomic_write(cert_path, response_retrieve)
                os.chmod(cert_path, 0o644)
            else:
                print(f"Retrieval failure for {subj}")
                print("The certificate can be retrieved directly from the InCommon Cert Manager interface.")
                print(f"CN {subj}, Self-enrollment Certificate ID (sslId): {request[0]}")
            
            print("-"*60)

    except SystemExit:
        raise
    except ValueError as exc:
        sys.exit(exc)
    except KeyboardInterrupt as exc:
        print(str(exc))
        sys.exit('''Interrupted by user\n''')
    except KeyError as exc:
        print(prog + ": error: " + f"Key {exc} not found in dictionary")
        sys.exit(1)
    except FileNotFoundException as exc:
        print(prog + ": error: " + str(exc) + ':' + exc.filename)
        sys.exit(1)
    except SSLError as exc:
        print(prog + ": " + str(exc))
        sys.exit('Please check for valid certificate.\n')
    except (IOError, FileWriteException, BadPassphraseException, AttributeError, EnvironmentError, ValueError, EOFError, SSLError, AuthenticationFailureException) as exc:
        print(prog + ": error: " + str(exc))
        sys.exit(1)
    except http.client.HTTPException as exc:
        print(str(exc))
        sys.exit(1)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    sys.exit(0)
