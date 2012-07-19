#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
This script is used to retrieve the certificates that are requested by the guests.
This script requires no authorizaion.It can check the status of the request and can
issue the certificate and the retrieve if it is in APPROVED state. However, it is
required to approve the certificate through webUI before running this script.
This script checks to see if the output file exists and allows user to correct it
once.
"""

import urllib
import httplib
import sys
import ConfigParser
import argparse
import json
import time
import re
import os

# Set up Option Parser
#

parser = argparse.ArgumentParser()
parser.add_argument(
    '-i',
    '--id',
    action='store',
    dest='id',
    required=True,
    help='Specify ID# of certificate to retrieve',
    metavar='ID',
    )
parser.add_argument(
    '-o',
    '--certfile',
    action='store',
    dest='certfile',
    required=False,
    help='Specify the output filename for the retrieved user certificate. Default is ./hostcert.pem'
        ,
    metavar='ID',
    default='./hostcert.pem',
    )

parser.add_argument(
    '-q',
    '--quiet',
    action='store_false',
    dest='verbose',
    default=True,
    required=False,
    help="don't print status messages to stdout",
    )
args = parser.parse_args()

# print "Parsing variables..."

global id, pem_filename
id = args.id

if os.path.exists(args.certfile):
    opt = \
        raw_input('This file already exists. Do you want to overwrite it? Y/N : \n'
                  )
    if opt == 'y' or opt == 'Y':
        pem_filename = args.certfile
    elif opt == 'n' or opt == 'N':
        pem_filename = raw_input('Please enter a different file name\n')
    else:
        sys.exit('Invalid option')
else:
    pem_filename = args.certfile

#
# Read from the ini file
#

Config = ConfigParser.ConfigParser()
Config.read('OSGTools.ini')
host = Config.get('OIMData', 'host')
requrl = Config.get('OIMData', 'returl')
appurl = Config.get('OIMData', 'appurl')
issurl = Config.get('OIMData', 'issurl')

content_type = Config.get('OIMData', 'content_type')

# Some vars for file operations

filetype = 'host-cert'
fileext = 'pkcs7'
filename = '%s.%s.%s' % (filetype, id, fileext)


# Build the connection to the web server - the request header, the parameters
# needed and then pass them into the server
#
# The data returned is in JSON format so to make it a little more human
# readable we pass it through the json module to pretty print it
#
# A WHILE loop exists to keep trying to retrieve the certificate if there
# is a delay in issuing
#
# Then we use a regexp to fix the munged up new lines that get returned
# and put the cert into the proper format, clipping of the extraneous
# JSON formatting and write the certificate file out
#

def connect_issue():
    params = urllib.urlencode({'host_request_id': id})
    headers = {'Content-type': content_type,
               'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}
    print 'Contacting Server to initiate certificate issuance. Please wait\n'
    newrequrl = Config.get('OIMData', 'issurl')
    conn = httplib.HTTPConnection(host)
    try:
        conn.request('POST', newrequrl, params, headers)
        time.sleep(10)
        response = conn.getresponse()
    except Exception, e:
        print 'Connection to %s failed: %s' % (newrequrl, e)
        raise e
    data = response.read()
    conn.close()

    if not 'OK' in data:
        print json.dumps(json.loads(data), sort_keys=True, indent=2)
        print '''Fatal error while issuing: Certificate request has failed. Goc staff has been
notified of this issue.
'''
        print 'You can open goc ticket to track this issue by going to https://ticket.grid.iu.edu\n'
        sys.exit(1)

    return


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
    print 'Connecting server to retrieve certificate...'
    params = urllib.urlencode({'host_request_id': id})
    headers = {'Content-type': content_type,
               'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}
    conn = httplib.HTTPConnection(host)
    try:
        conn.request('POST', requrl, params, headers)
        response = conn.getresponse()
    except httplib.HTTPException, e:
        print 'Connection to %s failed: %s' % (newurl, e)
        raise httplib.HTTPException
    data = response.read()
    if '"request_status":"REQUESTED"' in data:
        sys.exit('Certificate request in Requested state. Needs to be Approved first. Please contact RA to approve this certificate\n'
                 )
    elif '"request_status":"APPROVED"' in data:
        print 'Certificate request in Approved state. Needs to be issued first\n'
        connect_issue()

    if not 'PENDING' in response.reason:
        if not 'OK' in response.reason:
            print response.status, response.reason
            sys.exit(1)
    conn.close()

    try:
        conn.request('POST', requrl, params, headers)
        response = conn.getresponse()
    except httplib.HTTPException, e:
        print 'Connection to %s failed: %s' % (newurl, e)
        raise httplib.HTTPException
    data = response.read()

    while 'PENDING' in data:
        conn.request('POST', requrl, params, headers)
        try:
            response = conn.getresponse()
        except httplib.HTTPException, e:
            print 'Connection to %s failed: %s' % (newurl, e)
            raise httplib.HTTPException
        data = response.read()
        conn.close()
        if 'PENDING' in data:
            print 'Waiting for response from Certificate Authority. Please wait.\n'
            time.sleep(30)
            iterations = iterations + 1
            print 'Attempt:', iterations, ' Delay: ', iterations / 2, \
                ' minutes.'
            if iterations == 5:
                sys.exit('''Maximum number of attempts reached.
The script has failed and will now exit.
''')
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
    pkcs7raw = re.sub('\\\\n', '\n', pkcs7raw)
    pkcs7raw = pkcs7raw.partition('[')
    pkcs7raw = pkcs7raw[2]
    pkcs7raw = pkcs7raw.partition('"')
    pkcs7raw = pkcs7raw[2]
    pkcs7raw = pkcs7raw.partition('"')
    pkcs7raw = pkcs7raw[0]

    temp_filename = '%s.%s.%s' % (filetype, id, fileext)

    # pem_filename = '%s.%s.%s' % ('host-certs', id, 'pem')

    certfile = open(temp_filename, 'w+')
    certfile.write(pkcs7raw)
    certfile.close()
    os.system('openssl pkcs7 -print_certs -in ' + temp_filename
              + ' -out ' + pem_filename)
    os.remove(temp_filename)
    print 'Certificate written to %s \n' % pem_filename
    return


if __name__ == '__main__':
    connect_retrieve()
    sys.exit(0)
