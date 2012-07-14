#!/usr/bin/python
# -*- coding: utf-8 -*-

# $Id: ManageCertRequests.py 15033 2012-06-18 18:21:54Z jeremy $

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
    required=True,
    help="Specify Requestor's private key (PEM Format)",
    metavar='PKEY',
    )
parser.add_argument(
    '-ce',
    '--cert',
    action='store',
    dest='usercert',
    required=True,
    help="Specify Requestor's certificate (PEM Format)",
    metavar='CERT',
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

userprivkey = args.userprivkey
usercert = args.usercert
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
    connect()
    sys.exit(0)

