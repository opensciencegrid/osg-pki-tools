import httplib
import logging
import socket
import M2Crypto
import urllib

from json import dumps
from urlparse import urljoin

from ExceptionDefinitions import *
from utils import *

logger = logging.getLogger(__name__)

class InCommonApiClient():

    def __init__(self, base_url, ssl_context, *args, **kwargs):
        """base_url and api_timeout

        Args:
            base_url (string): Will be used to connect to the InCommon API (cert-auth) 
        """
        
        self.base_url = base_url
        self.connection = M2Crypto.httpslib.HTTPSConnection(base_url, strict=False, ssl_context=ssl_context)
    
    def closeConnection(self):
        self.connection.close()

    def post_request(self, url, headers, data):
        """
        Args:
            url (string): url to send the request
            data (json):body containing information
            headers (json): additional headers to complete the request
        """
        
        url = urljoin(self.base_url, url)
        
        logger.debug('posting to ' + url)
        logger.debug('data ' + str(data))
        
        params = urllib.urlencode(data, doseq=True)
        
        try:
            self.connection.request("POST", url, body=dumps(data), headers=headers)

            post_response = self.connection.getresponse()

            check_response_500(post_response)

            logger.debug('post response text ' + str(post_response.status) + ': ' + str(post_response.reason))

        except httplib.HTTPException as exc:
            charlimit_textwrap('Connection to %s failed : %s' % (url, exc))
            raise

        return post_response

    def get_request(self, url, headers):
        """
        Args:
            url (string): url to send the request
            headers (json): additional headers to complete the request
        """
        url = urljoin(self.base_url, url)

        logger.debug('requesting to ' + url)
        
        try:
            self.connection.request("GET", url, None, headers)
            get_response = self.connection.getresponse()
            
            check_response_500(get_response)
        
            logger.debug('get response text' + str(get_response.status) + ': ' + str(get_response.reason))
        except httplib.BadStatusLine as exc:
            raise
        except httplib.HTTPException as exc:
            charlimit_textwrap('Connection to %s failed : %s' % (url, exc))
            raise
       
        return get_response

