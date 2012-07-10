#!/usr/bin/python
 
# $Id: HostCertRequest-Guest.py 14967 2012-06-08 00:42:56Z jeremy $

import urllib
import httplib
import sys
import ConfigParser
import argparse
import json
import OpenSSL
from OpenSSL import crypto
from certgen import * #Lazy, I know
from pprint import pprint
""" 
This script is for guest (non-authenticated) requests for host certificates. 
It takes the arguments below to construct the CSR and send to OIM. It only 
does single requests and requires the retrieval (RetrieveCert.py)
to be run.

If you are not a grid admin and do not have your OIM certificate, you will 
have to run this script.

"""


# Set up Option Parser
#
parser = argparse.ArgumentParser()
parser.add_argument("-c", "--csr", action="store", dest="csr",default="gennew.csr",required= False,
				  help="Specify CSR name (default = gennew.csr)", metavar="CSR")
parser.add_argument("-k", "--key", action="store", dest="prikey",default="genprivate.key", required=False,	
				  help="Specify Private Key Name (default=genprivate.key)", metavar="PRIKEY")
parser.add_argument("-y", "--country", action="store", dest="country", required=False,default="",
				  help="Specify Country code for CSR (2 letter)", metavar="COUNTRY")
parser.add_argument("-s", "--state", action="store", dest="state", required=False, default="",
				  help="Specify State code for CSR (2 letter)", metavar="STATE")
parser.add_argument("-l", "--locality", action="store", dest="locality", required=False,default="",
				  help="Specify City for CSR", metavar="LOCALITY")
parser.add_argument("-o", "--org", action="store", dest="org",required=False,default="",
				  help="Specify Organization for CSR", metavar="ORG")
parser.add_argument("-u", "--orgunit", action="store", dest="orgunit", required=False,
				  help="Specify Organizational Unit for CSR", metavar="OU", default="")
parser.add_argument("-t", "--hostname", action="store", dest="hostname", required=True,
				  help="Specify hostname for CSR (FQDN)", metavar="CN")
parser.add_argument("-e", "--email", action="store", dest="email", required = True,
				  help="Email address to receive certificate", metavar="EMAIL")
parser.add_argument("-n", "--name", action="store", dest="name", required = True,
				  help="Name of user receiving certificate", metavar="NAME")
parser.add_argument("-p", "--phone", action="store", dest="phone", required = True,
				  help="Phone number of user receiving certificate", metavar="PHONE")
parser.add_argument("-q", "--quiet",action="store_false", dest="verbose", default=True,
                                  help="don't print status messages to stdout")
args = parser.parse_args()

#print "Parsing variables..."
global csr, prikey, country, state, locality, org, orgunit, hostname, email, name, phone#, config_items
country = args.country
state = args.state
locality = args.locality
org = args.org
orgunit = args.orgunit
hostname = args.hostname
email = args.email
name = args.name
phone = args.phone
csr = args.csr
prikey = args.prikey


################# Config items for key file write#########

ext="pem"
kname="hostkeyfile"

##########################################################

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
   try:
      conn.request("POST", requrl, params, headers)
      response = conn.getresponse()
   except httplib.HTTPException as e:
      print "Connection to %s failed: %s" %(requrl,repr(e))
      raise e
   if not "OK" in response.reason:
      print response.status, response.reason
      sys.exit(1)
   data = response.read()
   conn.close()
   print json.dumps(json.loads(data), sort_keys = True, indent = 2)

def check_input():
   if len(country) != 2 and country !="":
      sys.exit("\nExiting: Country code must be two characters")
   if state!="" and len(state) != 2:
      sys.exit("\nExiting: State code must be two characters")
   if country !="" and not country.isalpha():
      sys.exit("\nExiting: Country must be letters only")
   if state!="" and not state.isalpha():
      sys.exit("\nExiting: State must be letters only")
   if locality!="" and not locality.isalpha():
      sys.exit("\nExiting: Locality must be letters only")   
   if org!="" and not org.isalpha():
      sys.exit("\nExiting: Organization must be letters only")
   if orgunit!="" and not orgunit.isalpha():
      sys.exit("\nExiting: Organization unit must be letters only")


if __name__ == '__main__': 
   config_items={"CN": hostname,"emailAddress": email}
   if country!='':
      config_items.update({"C": country})
   if state!='':
      config_items.update({"ST": state})
   if locality!='':
      config_items.update({"L": locality})
   if org!='':
      config_items.update({"O": org})
   if orgunit!='':
      config_items.update({"OU":orgunit})

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
      keyname=kname+"."+ext
      repr(genprivate)
      ##### Writing private key####
      privkey=open(keyname,'wb')
      key=OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,genprivate)
      privkey.write(key)
      privkey.close()
      ###############################
      new_csr = createCertRequest(genprivate, digest="sha1", **config_items)
      
      csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, new_csr)
      csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '').replace('-----END CERTIFICATE REQUEST-----\n', '')
      connect()
   elif prikey != "genprivate.key":
      private_key = crypto.load_privatekey(crypto.FILETYPE_PEM,open(prikey,'r').read())                       
      new_csr = createCertRequest(private_key, digest="sha1", **config_items)
      csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, new_csr)
      csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '').replace('-----END CERTIFICATE REQUEST-----\n', '')
      connect()
   else:
      new_csr = crypto.load_certificate_request(crypto.FILETYPE_PEM,open(csr,'r').read()) 
      csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, new_csr)
      csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '').replace('-----END CERTIFICATE REQUEST-----\n', '') 
      connect()
   sys.exit(0)
        





