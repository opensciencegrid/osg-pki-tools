#! /usr/bin/env python

import sys
import pprint
import simplejson
import urllib
import httplib
import textwrap
import base64
import M2Crypto
import time

from osgpkitools import OSGPKIUtils
from OSGPKIUtils import CreateOIMConfig
from OSGPKIUtils import charlimit_textwrap
from OSGPKIUtils import check_response_500
from OSGPKIUtils import check_failed_response
from OSGPKIUtils import print_failure_reason_exit
from OSGPKIUtils import check_for_pending
from ExceptionDefinitions import *

class ConnectAPI(object):
    conn_defaults_dict = {'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}

    def __init__(self):
        """Set the initialization parameters."""
        return

    def request_unauthenticated(self, **arguments):
        """For unregistered user requests for a certificate
        INPUTS: Arguments (A dict)
                        1. content_type. (The type of content to be sent over to the server)
                        2. csr    (certificate signing request in PEM format).
                        3. phone  (Phone number for the user requesting certificate).
                        4. requrl (URL to connect to the server to request certificate).
                        5: host   (URL to connect to the server to initiate certificate request)
                        6. name   (Name of the requesting user)
                        7. email  (E-mail for the user).

        OUTPUT: request_id - Request ID for current Certificate request.
        """
        try:
            params = urllib.urlencode({
                'name': arguments['name'],
                'email': arguments['email'],
                'phone': arguments['phone'],
                'csrs': arguments['csr'],
                'request_comment': arguments['comment'],
                'request_ccs': arguments['cc_list'].split(','),
                })
            headers = {'Content-type': arguments['content_type'],
                       'User-Agent': ConnectAPI.conn_defaults_dict['User-Agent']}
            conn = httplib.HTTPConnection(arguments['host'])

            response = self.do_connect(conn, 'POST', arguments['requrl'], params, headers)
            data = response.read()
            check_failed_response(data)
            conn.close()

            if simplejson.loads(data)['detail'] == 'Nothing to report' \
                and simplejson.loads(data)['status'] == 'OK' in data:
                request_id = simplejson.loads(data)['host_request_id']
        except KeyError:
            raise
        except httplib.HTTPException:
            raise
        except Exception_500response, e:
            raise e
        except Exception, e:
            raise e
        return request_id

    def request_authenticated(self, bulk_csr, **arguments):
        """For registered user(gridadmin) requests for certificate.
                INPUTS: Arguments (A dict)
                        1. content_type (The type of content to be sent over to the server)
                        2. ssl_context  (SSL Context for M2Crypto)
                        3. hostsec      (URL for https connection to the server).
                        4. requrl       (URL to request certificate).

                BULK_CSR: Certificate Signing Requests in PEM format for multiple certificates.

        OUTPUT:  'reqid' - Request ID for current Certificate request.
        """
        try:
            params = urllib.urlencode({'csrs': bulk_csr}, doseq=True)
            headers = {'Content-type': arguments['content_type'],
                       'User-Agent': ConnectAPI.conn_defaults_dict['User-Agent']}
            conn = M2Crypto.httpslib.HTTPSConnection(arguments['hostsec'],
                    ssl_context=arguments['ssl_context'])

            response = self.do_connect(conn,'POST', arguments['requrl'], params, headers)
            data = response.read()
            if not 'OK' in response.reason:
                print_failure_reason_exit(data)
            conn.close()
            check_failed_response(data)
            return_data = simplejson.loads(data)
            for (key, value) in return_data.iteritems():
                if 'host_request_id' in key:
                    reqid = value
        except KeyError:
            raise
        except httplib.HTTPException:
            raise
        except Exception_500response, e:
            raise e
        except Exception, e:
            raise e
        return reqid


    def retrieve_authenticated(self, **arguments):
        """This function is used by the gridadmin scripts for fetching the
        cert strings in a raw string format.

        We retrieve the certificate from OIM after it has retrieved it from the CA
        This is where things tend to fall apart - if the delay is to long and the
        request to the CA times out, the whole script operation fails. I'm not
        terribly pleased with that at the moment, but it is out of my hands since
        a GOC staffer has to reset the request to be able to retrieve the
        certificate

        INPUT: arguments (As a dict)
               1. reqid        (The request ID for retrieving the user requested certificate).
               2. hostsec      (URL to connect to the server using HTTPS)
               3. content_type (The type of content to be sent over to the server)
               4. returl       (URL to retrieve certificate)

        RETURNS: PKCS7 Certificate String in raw format.
        """
        try:
            params = urllib.urlencode({'host_request_id': arguments['reqid']})
            headers = {'Content-type': arguments['content_type'],
                       'User-Agent': ConnectAPI.conn_defaults_dict['User-Agent']}
            conn = httplib.HTTPSConnection(arguments['hostsec'])
            response = self.do_connect(conn,'POST', arguments['returl'], params, headers)
            data = response.read()
            if not 'PENDING' in response.reason:
                if not 'OK' in response.reason:
                    raise NotOKException(simplejson.loads(data)['status'],simplejson.loads(data)['detail'].lstrip())
                    raise SystemExit

            iterations = 0
            while 'PENDING' in data:
                response = self.do_connect(conn,'POST', arguments['returl'], params, headers)
                data = response.read()
                iterations = check_for_pending(data, iterations, **arguments)

            check_failed_response(data)
            pkcs7raw = simplejson.dumps(simplejson.loads(data), sort_keys=True, indent=2)

        except KeyError, e:
            raise
        except httplib.HTTPException, e:
            raise
        except Exception_500response, e:
            raise e
        except NotOKException, e:
            raise e
        return simplejson.loads(data)['pkcs7s']

    def retrieve_unauthenticated(self, **arguments):
        """This function checks if the request by an unauthenticated user
        is in issued state. If it is in the issued state, it then retrieves
        the certificate, otherwise it calls the issue method to issue the
        certificate if it is in approved state.

        We retrieve the certificate from OIM after it has retrieved it from the CA
        This is where things tend to fall apart - if the delay is to long and the
        request to the CA times out, the whole script operation fails. I'm not
        terribly pleased with that at the moment, but it is out of my hands since
        a GOC staffer has to reset the request to be able to retrieve the
        certificate

        INPUT: arguments (As a dict)
               1. id           (request id for the certificate)
               2. returl       (URL to retrieve certificate from the server)
               3. content_type (The type of content to be sent over to the server)
               4. host         (URL to connect to the server)

        RETURNS: PKCS7 Certificate String in raw format.
        """
        try:
            params = urllib.urlencode({'host_request_id': arguments['id']})
            headers = {'Content-type': arguments['content_type'],
                       'User-Agent': ConnectAPI.conn_defaults_dict['User-Agent']}
            conn = httplib.HTTPConnection(arguments['host'])

            response = self.do_connect(conn,'POST', arguments['returl'], params, headers)
            data = response.read()

            if simplejson.loads(data).has_key('request_status'):
                if simplejson.loads(data)['request_status'] == 'REQUESTED':
                    raise NotApprovedException('Certificate request is in Requested state. \
                    Needs to be Approved first. Please contact GA to approve this certificate\n'
                            )
                else:
                    charlimit_textwrap('Certificate request is in Approved state. Needs to be issued first\n'
                                       )
                    self.issue(**arguments)

            conn = httplib.HTTPConnection(arguments['host'])
            response = self.do_connect(conn,'POST', arguments['returl'], params, headers)
            data = response.read()
            iterations = 0

            while 'PENDING' in data:
                conn.request('POST', arguments['returl'], params, headers)
                response = conn.getresponse()
                data = response.read()
                conn.close()
                iterations = check_for_pending(data, iterations, **arguments)
            check_failed_response(data)
            pkcs7raw = simplejson.loads(data)['pkcs7s'][0]

        except KeyError:
            raise
        except httplib.HTTPException:
            raise
        except Exception_500response, e:
            raise e
        except Exception,e:
            raise
        return pkcs7raw

    def issue(self, **arguments):
        """ Build the connection to the web server - the request header, the parameters
            needed and then pass them into the server
            The data returned is in JSON format so to make it a little more human
            readable we pass it through the json module to pretty print it

           INPUTS: arguments
                1. id           (Request id for the certificate request).
                2. content_type (The type of content to be sent over to the server)
                3. issurl       (URL to issue a certificate)
                4. host         (URL to connect to the server).

           OUTPUT: None
        """
        try:
            params = urllib.urlencode({'host_request_id': arguments['id']})
            headers = {'Content-type': arguments['content_type'],
                       'User-Agent': ConnectAPI.conn_defaults_dict['User-Agent']}

            newrequrl = arguments['issurl']
            conn = httplib.HTTPConnection(arguments['host'])
            conn.request('POST', newrequrl, params, headers)
            time.sleep(10) # Discussed with Rohan, he says it is needed otherwise the issuance of certificate does not happen.
            response = conn.getresponse()
            data = response.read()
            conn.close()
            if not 'OK' in data:
                raise NotOKException('Failed',simplejson.loads(data)['detail'])
                raise SystemExit
        except KeyError, e:
            raise
        except httplib.HTTPException, e:
            raise
        except NotOKException, e:
            raise

        return

    def approve(self, **arguments):

        """This function accepts an ssl_context instance which contains
        information about the established ssl connection
        and a dictionary consisting of all parameters and their values,
        It approves the request that is submitted to the OIM by connect_request.
        INPUTS: arguments
                1. reqid        (The request id for the certificate )
                2. content_type (The type of content to be sent over to the server)
                3. appurl       (URL to approve certificates)
                4. ssl_context  (SSL Context for M2Crypto)
                5. host         (URL to connect to the server)

        OUTPUT: None
        """
        try:
            action = 'approve'
            params = urllib.urlencode({'host_request_id': arguments['reqid']})
            headers = {'Content-type': arguments['content_type'],
                       'User-Agent': ConnectAPI.conn_defaults_dict['User-Agent']}
            conn = M2Crypto.httpslib.HTTPSConnection(arguments['host'],
                    ssl_context=arguments['ssl_context'])
            response = self.do_connect(conn,'POST', arguments['appurl'], params, headers)
            if not 'OK' in response.reason:
                raise NotOKException(response.status, response.reason)
            data = response.read()
            conn.close()
            issurl = arguments['issurl']
            if action == 'approve' and 'OK' in data:
                newrequrl = arguments['issurl']
                conn = M2Crypto.httpslib.HTTPSConnection(arguments['host'],
                        ssl_context=arguments['ssl_context'])

                conn.request('POST', newrequrl, params, headers)
                response = conn.getresponse()
                data = response.read()
                conn.close()
                check_failed_response(data)
            elif not 'OK' in data:
                raise NotOKException('Failed', simplejson.loads(data)['detail'])
        except KeyError:
            raise
        except httplib.HTTPException:
            raise
        except Exception_500response, e:
            print e.message
            raise e
        except NotOKException:
            raise

    def renew(self,**arguments):
        """This function connects to the user renew API and passes the DN
        and the serial number to API to get back the request ID.
        """

        print 'Connecting to server to renew certificate...'
        params = urllib.urlencode({'serial_id': arguments['serial_number'].strip('\n'),
                                   }, doseq=True)
        ### For testing purpose only###
        #params = urllib.urlencode({'user_request_id': '214'
        #                           }, doseq=True)
        ####
        headers = {'Content-type': arguments['content_type'],
                   'User-Agent': 'OIMGridAPIClient/0.1 (OIM Grid API)'}

        conn = M2Crypto.httpslib.HTTPSConnection(arguments['hostsec'],
                ssl_context=arguments['ssl_context'])
        try:
            conn.request('POST', arguments['renewurl'], params, headers)

            response = conn.getresponse()
        except httplib.HTTPException, e:
            charlimit_textwrap('Connection to %s failed : %s' % (requrl, e))
            raise e
        data = response.read()

        #This if block is to catch failures and would exit the script
        if not 'OK' in response.reason:
            print_failure_reason_exit(data)
        conn.close()
        check_failed_response(data)
        return_data = simplejson.loads(data)
        request_id = return_data['request_id']
        if not request_id:
            raise UnexpectedBehaviourException("Request Id not found in data. Script will now exit")
        arguments.update({'reqid': request_id})
        return arguments

    def do_connect(self, connection_Handle, http_type, url, parameters, headers):
        """Function to handle the connection to the web server.
           INPUTS:
           1. connection_handle (Instance to the created connection to the server.)
           2. http_type         ("GET or POST" method.)
           3. url               (URL to connect to the server.)
           4. parameters        (Parameters to be passed to the server.)
           5. headers           (Headers to be sent over to the server.)

           OUTPUT:
           response   : Dict containing the response from the server.
        """
        try:

            connection_Handle.request(http_type, url, parameters, headers)
            response = connection_Handle.getresponse()
            check_response_500(response)
            connection_Handle.close()
        except httplib.HTTPResponse:
            raise
        except Exception_500response , e:
            raise e
        return response
if __name__ == '__main__':
    pass
