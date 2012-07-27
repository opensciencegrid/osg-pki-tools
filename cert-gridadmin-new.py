#!/usr/bin/python
# -*- coding: utf-8 -*-

# $Id: ManageCertRequests.py 15033 2012-06-18 18:21:54Z jeremy $

"""
The intended user for this script is the GridAdmin.
Approve (request) is done when the vetting process is succes and the request can be approved.
Reject (request) is done when during the vetting process the RA/GA has the opinion that the request
has bogus or incorrect information and cannot be approved. this action is taken by the RA/GA.
Cancel (request) is done when the request is made by the user and the user decides to withdraw it.
This action is taken by the user.
"""

import urllib
import httplib
import sys
import ConfigParser
import argparse
import json

from certgen import *  # Lazy, I know

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
    help="Specify Requestor's certificate (PEM Format). If not specified will take the value of X509_USER_KEY or $HOME/.globus/userkey.pem"
        ,
    metavar='CERT',
    default='',
    )
parser.add_argument(
    '-a',
    '--action',
    action='store',
    dest='action',
    required=True,
    help='Action to take (reject, cancel, revoke',
    metavar='ACTION',
    )
parser.add_argument(
    '-i',
    '--id',
    action='store',
    dest='id',
    required=True,
    help='Specify ID# of certificate request to act on',
    metavar='ID',
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

# print "Parsing variables..."

if args.userprivkey == '':
    try:
        userprivkey = os.environ['X509_USER_KEY']
    except:
        userprivkey = str(os.environ['HOME']) + '/.globus/userkey.pem'
else:
    userprivkey = args.userprivkey

if os.path.exists(userprivkey):
    pass
else:
    sys.exit('Unable to locate the private key file:' + userprivkey)

if args.usercert == '':
    try:
        usercert = os.environ['X509_USER_CERT']
    except:
        usercert = str(os.environ['HOME']) + '/.globus/usercert.pem'
else:
    usercert = args.usercert

if os.path.exists(usercert):
    pass
else:
    sys.exit('Unable to locate the user certificate file:' + usercert)

action = args.action
id = args.id

#
# Read from the ini file
#

Config = ConfigParser.ConfigParser()
Config.read('OSGTools.ini')
host = Config.get('OIMData', 'hostsec')
if action == 'reject':
    requrl = Config.get('OIMData', 'revurl')
elif action == 'approve':
    requrl = Config.get('OIMData', 'appurl')
elif action == 'cancel':
    requrl = Config.get('OIMData', 'canurl')
else:
    sys.exit('''
Exiting: Action must be reject, approve, or cancel.
''')

content_type = Config.get('OIMData', 'content_type')


def connect():
    print '\nConnecting to server...'
    params = urllib.urlencode({'host_request_id': id})
    headers = {'Content-type': content_type,
               'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}
    conn = httplib.HTTPSConnection(host, key_file=userprivkey,
                                   cert_file=usercert)
    conn.request('POST', requrl, params, headers)
    response = conn.getresponse()
    if not 'OK' in response.reason:
        print response.status, response.reason
        sys.exit(1)
    data = response.read()
    conn.close()
    print json.dumps(json.loads(data), sort_keys=True, indent=2)

    if action == 'approve' and 'OK' in data:
        print '''
Contacting Server to initiate certificate issuance.
'''
        newrequrl = Config.get('OIMData', 'issurl')
        conn = httplib.HTTPSConnection(host, key_file=userprivkey,
                cert_file=usercert)
        conn.request('POST', newrequrl, params, headers)
        response = conn.getresponse()
        if not 'OK' in response.reason:
            print response.status, response.reason
            sys.exit(1)
        data = response.read()
        conn.close()
        print json.dumps(json.loads(data), sort_keys=True, indent=2)
    else:
        sys.exit(0)


if __name__ == '__main__':
    try:
        connect()
    except Exception, e:
        sys.exit('''Uncaught Exception.
Please report the bug to goc@opensciencegrid.org. We would address your issue at the earliest.
'''
                 )
    sys.exit(0)

