#!/usr/bin/python

# $Id: BulkGen.py 15033 2012-06-18 18:21:54Z jeremy $


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

from OpenSSL import crypto
from certgen import * #Lazy, I know

"""
This script is for authenticated (via OSG issued peraonal certificate) requests
for host certificates. It takes the arguments below to construct the CSR and send
to OIM. Then it automatically approves and issues the certificate and attempts
to retrieve it.

The completed certificate will be in a directory called "certificates" in the
current working directory (obtained from getcwd()). It will write the cert
out in a standard format keyed by the request ID.

 Usage: BulkGen.py [options]

 Options:
  -h, --help                    Show this help message and exit
  -pk PKEY,  --pkey=PKEY         Requestor's private key (PEM Format)
  -ce  CERT,  --cert=CERT         Requestor's user certificate (PEM Format)
  -f  HOSTFILE --hostfile=filename Filename with one hostname per line (default = hosts.txt)
  -y  COUNTRY, --country=COUNTRY Country code for CSR (2 letter)
  -s  STATE, --state=state       State code for CSR (2 letter)
  -l  LOCALITY, --locality=city  City name for CSR
  -o  ORG, --organization=ORG    Organization name for CSR
  -u  OU, --orgunit=OU           Organizational unit for CSR (default = OSG)
  -e  EMAIL, --email=EMAIL       Email address of requestor
  -n  NAME, --name=NAME          Name of user of requestor
  -p  PHONE --phone              Phone Number of requestor
  -q, --quiet                   Don't print status messages to stdout
"""

# Set up Option Parser
#
parser = argparse.ArgumentParser()
parser.add_argument("-pk", "--pkey",
                    action="store", dest="userprivkey", required = True,
                    help="Specify Requestor's private key (PEM Format)",
                    metavar="PKEY")
parser.add_argument("-ce",  "--cert",
                    action="store", dest="usercert", required = True,
                    help="Specify Requestor's certificate (PEM Format)",
                    metavar="CERT")
parser.add_argument("-f",  "--hostfile",
                    action="store", dest="hostfile", required = True,
                    help="Filename with one hostname per line",
                    metavar="HOSTFILE", default="hosts.txt")
parser.add_argument("-y",  "--country",
                    action="store", dest="country", required = True,
                    help="Specify Country code for CSR (2 letter)",
                    metavar="COUNTRY", default="US")
parser.add_argument("-s", "--state",
                    action="store", dest="state", required = True,
                    help="Specify State code for CSR (2 letter)",
                    metavar="STATE")
parser.add_argument("-l",  "--locality",
                    action="store", dest="locality", required = True,
                    help="Specify City for CSR",
                    metavar="LOCALITY")
parser.add_argument("-o",  "--org",
                    action="store", dest="org", required = True,
                    help="Specify Organization for CSR",
                    metavar="ORG")
parser.add_argument("-u", "--orgunit",
                    action="store", dest="orgunit", required = True,
                    help="Specify Organizational Unit for CSR (default OSG)",
                    metavar="OU", default="OSG")
parser.add_argument("-e", "--email",
                    action="store", dest="email", required = True,
                    help="Email address to receive certificate",
                    metavar="EMAIL")
parser.add_argument("-n",  "--name",
                    action="store", dest="name", required = True,
                    help="Name of user receiving certificate",
                    metavar="NAME")
parser.add_argument("-p", "--phone",
                    action="store", dest="phone", required = True,
                    help="Phone number of user receiving certificate",
                    metavar="PHONE")
parser.add_argument("-q", "--quiet",
                    action="store_false", dest="verbose", default=True,
                    help="don't print status messages to stdout")
args = parser.parse_args()


global country, state, locality, org, orgunit, hostname, domain, email, name, phone
userprivkey = args.userprivkey
usercert = args.usercert
hostfile = args.hostfile
country = args.country
state = args.state
locality = args.locality
org = args.org
orgunit = args.orgunit
email = args.email
name = args.name
phone = args.phone

#
# Read from the ini file
#
Config = ConfigParser.ConfigParser()
Config.read("OSGTools.ini")
host = Config.get("OIMData", "hostsec")
requrl = Config.get("OIMData", "requrl")
appurl = Config.get("OIMData", "appurl")
issurl = Config.get("OIMData", "issurl")
returl = Config.get("OIMData", "returl")
content_type = Config.get("OIMData", "content_type")

# Some vars for file operations
filetype = "pkcs7-cert"
fileext = "pem"
certdir = "certificates"

# Checking to make sure that the users give values that won't crash the
# CSR generation

def check_input():
    if len(country) != 2:
       sys.exit("\nExiting: Country code must be two characters")
    if len(state) != 2:
       sys.exit("\nExiting: State code must be two characters")
    if not country.isalpha():
       sys.exit("\nExiting: Country must be letters only")
    if not state.isalpha():
       sys.exit("\nExiting: State must be letters only")
    if not locality.isalpha():
       sys.exit("\nExiting: Locality must be letters only")
    if not org.isalpha():
       sys.exit("\nExiting: Organization must be letters only")
    if not orgunit.isalpha():
       sys.exit("\nExiting: Organization unit must be letters only")

# We make the request here, causing the generation of the CSR and then
# pass the ID returned from the server along. The ID is the key that OIM
# uses for all certificate operations via the API
#
def connect_request():
    print "Connecting to server to request certificate..."
    global id
    params = urllib.urlencode({
	'name': name,
	'email': email,
	'phone': phone,
	'csrs': csr,})
    headers = {'Content-type': content_type,
	'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}
    conn = httplib.HTTPSConnection(host, key_file = userprivkey, cert_file = usercert)
    conn.request("POST", requrl, params, headers)
    response = conn.getresponse()
    if not "OK" in response.reason:
       print response.status, response.reason
       print json.dumps(json.loads(data), sort_keys = True, indent = 2)
    data = response.read()
    conn.close()
    if "FAILED" in data:
	  print json.dumps(json.loads(data), sort_keys = True, indent = 2)
	  print "Fatal error: Certificate request has failed. Goc staff has been\nnotified of this issue."
	  print "You can open a GOC ticket to track this issue by going to\n https://ticket.grid.iu.edu\n"
	  sys.exit(1)
    return_data = json.loads(data)
    for key, value in return_data.iteritems():
	if "host_request_id" in key:
	    id = value

# ID from the request is passed in here via secure connection and the request
# gets approved automatically since it's a bulk request. We also issue the
# certificate (i.e. OIM contacts the CA on our behalf to get the cert) in this
# function
#
def connect_approve():
    print "Connecting to server to approve certificate..."
    action = "approve"
    params = urllib.urlencode({
	'host_request_id': id,
	     })
    headers = {'Content-type': content_type,
	'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}
    conn = httplib.HTTPSConnection(host, key_file = userprivkey, cert_file = usercert)
    conn.request("POST", appurl, params, headers)
    response = conn.getresponse()
    if not "OK" in response.reason:
       print response.status, response.reason
    data = response.read()
    conn.close()
    if (action == "approve") and ("OK" in data):
       print "Contacting Server to initiate certificate issuance."
       newrequrl = Config.get("OIMData", "issurl")
       conn = httplib.HTTPSConnection(host, key_file = userprivkey, cert_file = usercert)
       conn.request("POST", newrequrl, params, headers)
       response = conn.getresponse()
       data = response.read()
       conn.close()
       if "FAILED" in data:
	  print json.dumps(json.loads(data), sort_keys = True, indent = 2)
	  print "Fatal error: Certificate request has failed. Goc staff has been\nnotified of this issue.\n"
	  print "You can open goc ticket to track this issue by going to https://ticket.grid.iu.edu\n"
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
    print "Issuing certificate..."
    params = urllib.urlencode({
	'host_request_id': id,
	     })
    headers = {'Content-type': content_type,
	'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}
    conn = httplib.HTTPSConnection(host)
    conn.request("POST", returl, params, headers)
    response = conn.getresponse()
    if not "PENDING" in response.reason:
       if not "OK" in response.reason:
	  print response.status, response.reason
    data = response.read()
    conn.close()

    while "PENDING" in data:
	conn.request("POST", returl, params, headers)
	response = conn.getresponse()
	data = response.read()
	conn.close()
	if "PENDING" in data:
	    print "Waiting for response from Certificate Authority. Please wait."
	    time.sleep(30)
	    iterations = iterations + 1
	    print "Attempt:", iterations, " Delay: ", iterations/2, " minutes."
	else:
	     pass


    pkcs7raw = json.dumps(json.loads(data), sort_keys = True, indent = 2)

    if "FAILED" in data:
	print "Fatal error: Certificate request has failed. Goc staff has been\nnotified of this issue."
	print "You can open goc ticket to track this issue by going to https://ticket.grid.iu.edu\n"
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
    pkcs7raw = pkcs7raw.partition('\"')
    pkcs7raw = pkcs7raw[2]
    pkcs7raw = pkcs7raw.partition('\"')
    pkcs7raw = pkcs7raw[0]

    filename = "%s.%s.%s" % (filetype,id,fileext)
    cwd = os.getcwd()
    os.chdir(certdir)
    print "Writing to:", certdir
    certfile = open(filename, 'w+')
    certfile.write(pkcs7raw)
    certfile.close()
    os.chdir(cwd)
    print "Certificate written to ", filename, "\n"

def create_certificate():
    global csr
    print "Generating certificate..."
    genprivate = createKeyPair(TYPE_RSA, 2048)
    new_csr = createCertRequest(genprivate, digest="md5", **config_items)
    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, new_csr)
    csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '').replace('-----END CERTIFICATE REQUEST-----\n', '')

if __name__ == '__main__':
	check_input()
	print "Creating Certificate Directory (if necessary):", certdir
	try:
	   os.makedirs(certdir)
	except OSError as exc:
	   if exc.errno == errno.EEXIST:
	      pass
	   else: raise

	hosts = open(hostfile)
	for line in hosts:
	    line = line.rstrip('\n')
	    config_items = {"C": country, "ST": state, "L": locality, "O": org, "OU": orgunit, "CN": line, "emailAddress": email}
	    print "Beginning request process for", line
	    create_certificate()
	    connect_request()
	    connect_approve()
	    connect_retrieve()

	sys.exit(0)
