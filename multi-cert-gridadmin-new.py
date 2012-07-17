#!/usr/bin/python
# -*- coding: utf-8 -*-

import urllib
import httplib
import sys
import ConfigParser
import argparse
import json
import time
import re
import os
import errno
import getpass
import StringIO
import OpenSSL

from OpenSSL import crypto
from certgen import *

# Set up Option Parser
#

parser = argparse.ArgumentParser()
parser.add_argument(
    '-pk',
    '--pkey',
    action='store',
    dest='userprivkey',
    required=False,
    help="Specify Requestor's private key (PEM Format). If not specified will take the value of X509_USER_KEY or $HOME/.globus/userkey.pem"
        ,
    metavar='PKEY',
    default='',
    )
parser.add_argument(
    '-ce',
    '--cert',
    action='store',
    dest='usercert',
    required=False,
    help="Specify Requestor's certificate (PEM Format). If not specified will take the value of X509_USER_CERT or $HOME/.globus/usercert.pem"
        ,
    metavar='CERT',
    )
parser.add_argument(
    '-f',
    '--hostfile',
    action='store',
    dest='hostfile',
    required=True,
    help='Filename with one hostname per line',
    metavar='HOSTFILE',
    default='hosts.txt',
    )
parser.add_argument(
    '-e',
    '--email',
    action='store',
    dest='email',
    required=True,
    help='Email address to receive certificate',
    metavar='EMAIL',
    )
parser.add_argument(
    '-n',
    '--name',
    action='store',
    dest='name',
    required=True,
    help='Name of user receiving certificate',
    metavar='NAME',
    )
parser.add_argument(
    '-p',
    '--phone',
    action='store',
    dest='phone',
    required=True,
    help='Phone number of user receiving certificate',
    metavar='PHONE',
    )
parser.add_argument(
    '-q',
    '--quiet',
    action='store_false',
    dest='verbose',
    default=True,
    help="don't print status messages to stdout",
    )
args = parser.parse_args()

global hostname, domain, email, name, phone, outkeyfile

if args.userprivkey == '':
    try:
        userprivkey = os.environ('X509_USER_KEY')
    except:
        userprivkey = str(os.environ('HOME')) + '/.globus/userkey.pem'
else:
    userprivkey = args.userprivkey

if os.path.exists(userprivkey):
    pass
else:
    sys.exit('Unable to locate the private key file:' + userprivkey)

if args.usercert == '':
    try:
        usercert = os.environ('X509_USER_CERT')
    except:
        usercert = str(os.environ('HOME')) + '/.globus/usercert.pem'
else:
    usercert = args.usercert

if os.path.exists(usercert):
    pass
else:
    sys.exit('Unable to locate the user certificate file:' + usercert)

hostfile = args.hostfile
email = args.email
name = args.name
phone = args.phone

#
# Read from the ini file
#

Config = ConfigParser.ConfigParser()
Config.read('OSGTools.ini')
host = Config.get('OIMData', 'hostsec')
requrl = Config.get('OIMData', 'requrl')
appurl = Config.get('OIMData', 'appurl')
issurl = Config.get('OIMData', 'issurl')
returl = Config.get('OIMData', 'returl')
content_type = Config.get('OIMData', 'content_type')

# Some vars for file operations

filetype = 'pkcs7-cert'
fileext = 'pem'
certdir = 'certificates'

# Checking to make sure that the users give values that won't crash the

outkeyfile = userprivkey + '_temp'


#################################################

def get_passphrase(userprivkey):
    os.system('openssl rsa -in ' + userprivkey + ' -out ' + outkeyfile)


# We make the request here, causing the generation of the CSR and then
# pass the ID returned from the server along. The ID is the key that OIM
# uses for all certificate operations via the API
#

def connect_request(bulk_csr):
    print 'Connecting to server to request certificate...'
    global id
    params = urllib.urlencode({
        'name': name,
        'email': email,
        'phone': phone,
        'csrs': bulk_csr,
        })
    headers = {'Content-type': content_type,
               'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}

    conn = httplib.HTTPSConnection(host, key_file=outkeyfile,
                                   cert_file=usercert)
    try:
        conn.request('POST', requrl, params, headers)
        response = conn.getresponse()
    except httplib.HTTPException, e:

        print 'Connection to %s failed : %s' % (requrl, e)
        raise e

    if not 'OK' in response.reason:
        print response.status, response.reason
        print json.dumps(json.loads(data), sort_keys=True, indent=2)
    data = response.read()
    conn.close()
    if 'FAILED' in data:
        print json.dumps(json.loads(data), sort_keys=True, indent=2)
        print 'Fatal error: Certificate request has failed. Goc staff has been\nnotified of this issue.'
        print '''You can open a GOC ticket to track this issue by going to
 https://ticket.grid.iu.edu
'''
        sys.exit(1)
    return_data = json.loads(data)
    print return_data
    for (key, value) in return_data.iteritems():
        if 'host_request_id' in key:
            id = value
            print 'Id is:', id


# ID from the request is passed in here via secure connection and the request
# gets approved automatically since it's a bulk request. We also issue the
# certificate (i.e. OIM contacts the CA on our behalf to get the cert) in this
# function
#

def connect_approve():
    print 'Connecting to server to approve certificate...'
    action = 'approve'
    params = urllib.urlencode({'host_request_id': id})
    headers = {'Content-type': content_type,
               'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}
    conn = httplib.HTTPSConnection(host, key_file=outkeyfile,
                                   cert_file=usercert)

    try:
        conn.request('POST', appurl, params, headers)
        response = conn.getresponse()
    except httplib.HTTPException, e:
        print 'Connection to %s failed: %s' % (appurl, repr(e))
        raise e

    if not 'OK' in response.reason:
        print response.status, response.reason
        sys.exit(1)
    data = response.read()
    conn.close()
    if action == 'approve' and 'OK' in data:
        print 'Contacting Server to initiate certificate issuance.'
        newrequrl = Config.get('OIMData', 'issurl')
        conn = httplib.HTTPSConnection(host, key_file=outkeyfile,
                cert_file=usercert)
        try:
            conn.request('POST', newrequrl, params, headers)
            response = conn.getresponse()
        except httplib.HTTPException, e:
            print 'Connection to %s failed: %s' % (newrequrl, e)
            raise e
        data = response.read()
        conn.close()
        if 'FAILED' in data:
            print json.dumps(json.loads(data), sort_keys=True, indent=2)
            print '''Fatal error: Certificate request has failed. Goc staff has been
notified of this issue.
'''
            print 'You can open goc ticket to track this issue by going to https://ticket.grid.iu.edu\n'
            sys.exit(1)
    else:
        sys.exit(0)


# Here's where things have gotten dicey during the testing phase -
# We retrieve the certificate from OIM after it has retrieved it from the CA
# This is where things tend to fall apart - if the delay is to long and the
# request to the CA times out, the whole script operation fails. I'm not
# terribly pleased with that at the moment, but it is out of my hands since
# a GOC staffer has to reset the request to be able to retrieve the
# certificate
#

def connect_retrieve():
    iterations = 1
    print 'Issuing certificate...'
    params = urllib.urlencode({'host_request_id': id})
    headers = {'Content-type': content_type,
               'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}
    conn = httplib.HTTPSConnection(host)
    try:
        conn.request('POST', returl, params, headers)
        response = conn.getresponse()
    except httplib.HTTPException, e:
        print 'Connection to %s failed: %s' % (newurl, e)
        raise httplib.HTTPException
    if not 'PENDING' in response.reason:
        if not 'OK' in response.reason:
            print response.status, response.reason
            sys.exit(1)
    data = response.read()
    conn.close()
    print data
    while 'PENDING' in data:
        conn.request('POST', returl, params, headers)
        try:
            response = conn.getresponse()
        except httplib.HTTPException, e:
            print 'Connection to %s failed: %s' % (newurl, e)
            raise httplib.HTTPException
        data = response.read()
        conn.close()
        if 'PENDING' in data:
            print 'Waiting for response from Certificate Authority. Please wait.'
            time.sleep(30)
            iterations = iterations + 1
            print 'Attempt:', iterations, ' Delay: ', iterations / 2, \
                ' minutes.'
        else:
            pass

    pkcs7raw = json.dumps(json.loads(data), sort_keys=True, indent=2)
    if 'FAILED' in data:
        print 'Fatal error: Certificate request has failed. Goc staff has been\nnotified of this issue.'
        print 'You can open goc ticket to track this issue by going to https://ticket.grid.iu.edu\n'
        sys.exit(1)

    # The slice and dice on the JSON output to get the certificate out
    # happens here - the problem is that the new lines are getting all screwy
    # in the output from OIM. We stringify the data, replace all the text
    # newline characters with actual new lines and the strip off the
    # extra data. There's probably a more efficient way to do this, but this
    # was the quick and dirty solution.
    #

    pkcs7raw = str(pkcs7raw)
    print pkcs7raw
    pkcs7raw = re.sub('\\\\n', '\n', pkcs7raw)
    pkcs7raw = pkcs7raw.partition('[')
    pkcs7raw = pkcs7raw[2]
    pkcs7raw = pkcs7raw.partition('"')
    pkcs7raw = pkcs7raw[2]
    pkcs7raw = pkcs7raw.partition('"')
    pkcs7raw = pkcs7raw[0]

    filename = '%s.%s.%s' % (filetype, id, fileext)
    pem_filename = '%s.%s.%s' % ('host-certs', id, 'pem')
    cwd = os.getcwd()
    os.chdir(certdir)
    print 'Writing to:', certdir
    certfile = open(filename, 'w+')
    certfile.write(pkcs7raw)
    certfile.close()
    os.system('openssl pkcs7 -print_certs -in ' + filename + ' -out '
              + pem_filename)
    os.remove(filename)
    os.chdir(cwd)
    print 'Certificate written to %s \n' % pem_filename


def create_certificate(line):

    # global csr

    print 'Generating certificate...'
    genprivate = createKeyPair(TYPE_RSA, 2048)
    keyname = line + '-key.pem'

    # #### Writing private key####

    privkey = open(keyname, 'wb')
    key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
            genprivate)
    privkey.write(key)
    privkey.close()

    new_csr = createCertRequest(genprivate, digest='sha1',
                                **config_items)
    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, new_csr)
    csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', ''
                      ).replace('-----END CERTIFICATE REQUEST-----\n',
                                '')
    return csr


if __name__ == '__main__':
    get_passphrase(userprivkey)
    print 'Creating Certificate Directory (if necessary):', certdir
    try:
        os.makedirs(certdir)
    except OSError, exc:
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise

    config_items = {'emailAddress': email}

    # ############################# Pipelining the bulk Certificate request process to send them at once##################################

    bulk_csr = ''
    count = 0
    hosts = open(hostfile, 'rb')
    for line in hosts:
        count += 1
        line = line.rstrip('\n')
        config_items.update({'CN': line})  # ### New Config item list for every host#######
        print 'Beginning request process for', line
        csr = create_certificate(line)
        bulk_csr = bulk_csr + csr  # + '\n'
        if count == 50:
            connect_request(bulk_csr)
            connect_approve()
            connect_retrieve()
            bulk_csr = ''
            count = 0

    # ####################################################################################################################################

    if count != 0 and count != 50:
        print bulk_csr
        connect_request(bulk_csr)
        connect_approve()
        connect_retrieve()
    hosts.close()
    os.remove(outkeyfile)
    sys.exit(0)

