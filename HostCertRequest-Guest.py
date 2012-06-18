#!/usr/bin/python
 
# $Id: HostCertRequest-Guest.py 14967 2012-06-08 00:42:56Z jeremy $

import urllib
import httplib
import sys
import ConfigParser
import argparse
import json

from OpenSSL import crypto
from certgen import * #Lazy, I know

""" 
This script is for guest (non-authenticated) requests for host certificates. 
It takes the arguments below to construct the CSR and send to OIM. It only 
does single requests and requires the retrieval (RetrieveCert.py)
to be run.

If you are not a grid admin and do not have your OIM certificate, you will 
have to run this script.

 Usage: HostCertRequest.py [options]

 Options:
  -h, --help                    show this help message and exit
  -c CSR,   --csr=CSR           Read CSR from file (optional - default = new.csr)
  -k KEY,   --key=KEY           Read KEY from file (optional - detault = genprivate.key)
  -y COUNTRY, --country=COUNTRY Country code for CSR (2 letter)
  -s STATE, --state=state       State code for CSR (2 letter)
  -l LOCALITY, --locality=city  City name for CSR
  -o ORG, --organization=ORG    Organization name for CSR
  -u OU, --orgunit=OU           Organizational unit for CSR (default = OSG)
  -t CN, --host=CN              Host name for CSR (FQDN)
  -e EMAIL, --email=EMAIL       Email address to receive certificate
  -n NAME, --name=NAME          Name of user receiving certificate
  -p phone# --phone             Name of organizational unit [optional]
  -q, --quiet           don't print status messages to stdout
"""


# Set up Option Parser
#
parser = argparse.ArgumentParser()
parser.add_argument("-c", "--csr", action="store", dest="csr",
				  help="Specify CSR name (default = gennew.csr)", metavar="CSR")
parser.add_argument("-k", "--key", action="store", dest="prikey",
				  help="Specify Private Key Name (default=genprivate.key)", metavar="PRIKEY")
parser.add_argument("-y", "--country", action="store", dest="country",
				  help="Specify Country code for CSR (2 letter)", metavar="COUNTRY")
parser.add_argument("-s", "--state", action="store", dest="state",
				  help="Specify State code for CSR (2 letter)", metavar="STATE")
parser.add_argument("-l", "--locality", action="store", dest="locality",
				  help="Specify City for CSR", metavar="LOCALITY")
parser.add_argument("-o", "--org", action="store", dest="org",
				  help="Specify Organization for CSR", metavar="ORG")
parser.add_argument("-u", "--orgunit", action="store", dest="orgunit",
				  help="Specify Organizational Unit for CSR (default OSG)", metavar="OU", default="OSG")
parser.add_argument("-t", "--hostname", action="store", dest="hostname",
				  help="Specify hostname for CSR (FQDN)", metavar="CN")
parser.add_argument("-e", "--email", action="store", dest="email", required = True,
				  help="Email address to receive certificate", metavar="EMAIL")
parser.add_argument("-n", "--name", action="store", dest="name",
				  help="Name of user receiving certificate", metavar="NAME")
parser.add_argument("-p", "--phone", action="store", dest="phone",
				  help="Phone number of user receiving certificate", metavar="PHONE")
parser.add_argument("-q", "--quiet",action="store_false", dest="verbose", default=True,
                                  help="don't print status messages to stdout")
args = parser.parse_args()

#print "Parsing variables..."
global csr, prikey, country, state, locality, org, orgunit, hostname, email, name, phone
csr = args.csr
prikey = args.prikey
country = args.country
state = args.state
locality = args.locality
org = args.org
orgunit = args.orgunit
hostname = args.hostname
email = args.email
name = args.name
phone = args.phone
if (csr == None):
   csr = "gennew.csr"
if (prikey == None):
   prikey = "genprivate.key"
config_items = {"C": country, "ST": state, "L": locality, "O": org, "OU": orgunit, "CN": hostname, "emailAddress": email}

#
# Read from the ini file
#
Config = ConfigParser.ConfigParser()
Config.read("OSGTools.ini")
host = Config.get("OIMData", "host")
requrl = Config.get("OIMData", "requrl")
content_type = Config.get("OIMData", "content_type")

# Build the connection to the web server - the request header, the parameters
# needed and then pass them into the server
# 
# The data returned is in JSON format so to make it a little more human 
# readable we pass it through the json module to pretty print it
#
def connect():
    print "\nConnecting to server..."
    params = urllib.urlencode({
        'name': name,
        'email': email,
        'phone': phone,
        'csrs': csr,})
    headers = {'Content-type': content_type,
        'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}
    conn = httplib.HTTPConnection(host)
    conn.request("POST", requrl, params, headers)
    response = conn.getresponse()
    if not "OK" in response.reason:
       print response.status, response.reason
    data = response.read()
    conn.close()
    print json.dumps(json.loads(data), sort_keys = True, indent = 2)

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


if __name__ == '__main__': 
        if csr == "gennew.csr":
           check_input()
        #
        # Three options for the CSR request
        # 1. User provides neither private key nor CSR
        # 2. User provides private key but need to create the CSR
        # 3. User provides both private key and CSR and we just need to
        #    dump it and strip the text lines for the server
        #
        if prikey == "genprivate.key" and csr == "gennew.csr":
           genprivate = createKeyPair(TYPE_RSA, 2048)
           new_csr = createCertRequest(genprivate, digest="md5", **config_items)
           csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, new_csr)
           csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '').replace('-----END CERTIFICATE REQUEST-----\n', '')
           connect()
        elif prikey != "genprivate.key":
           private_key = crypto.load_privatekey(crypto.FILETYPE_PEM,open(prikey,'r').read())                       
           new_csr = createCertRequest(private_key, digest="md5", **config_items)
           csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, new_csr)
           csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '').replace('-----END CERTIFICATE REQUEST-----\n', '')
           connect()
        else:
           new_csr = crypto.load_certificate_request(crypto.FILETYPE_PEM,open(csr,'r').read()) 
           csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, new_csr)
           csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '').replace('-----END CERTIFICATE REQUEST-----\n', '') 
           connect()
        sys.exit(0)
        





