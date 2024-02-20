import http.client
import logging
import socket
import ssl
import urllib3
import urllib.parse

from json import dumps

from . import utils
from .ExceptionDefinitions import *

prog = "osg-incommon-cert-request"

logger = logging.getLogger(__name__)

class InCommonApiClient():

    def __init__(self, base_url, ssl_context, *args, **kwargs):
        """base_url and api_timeout

        Args:
            base_url (string): Will be used to connect to the InCommon API (cert-auth) 
            ssl_context (object): urllib3 SSL context including user credentials
        """
        
        if not base_url.startswith("http"):
            base_url = "https://" + base_url
        self.base_url = base_url

        self.http = urllib3.PoolManager(ssl_context=ssl_context,
                        ca_certs=ssl.get_default_verify_paths().cafile,
                        timeout=urllib3.util.Timeout(connect=2, read=10))
    
    def close_connection(self):
        self.http.clear()

    def post_request(self, url, headers, data):
        """
        Args:
            url (string): url to send the request
            data (json):body containing information
            headers (json): additional headers to complete the request
        """
        
        url = urllib.parse.urljoin(self.base_url, url)
        
        logger.debug('posting to ' + url)
        logger.debug('headers ' + str(headers))
        logger.debug('post data ' + str(data))
        
        params = urllib.parse.urlencode(data, doseq=True)
        
        try:
            post_response = self.http.request("POST", url, body=dumps(data), headers=headers)
            utils.check_response_500(post_response)
            logger.debug('post response status ' + str(post_response.status) + ': ' + str(post_response.reason))
        except http.client.HTTPException as exc:
            print((prog + f": error: post to {url} failed : {exc}"))
            raise

        return post_response

    def get_request(self, url, headers):
        """
        Args:
            url (string): url to send the request
            headers (json): additional headers to complete the request
        """
        url = urllib.parse.urljoin(self.base_url, url)

        logger.debug('requesting to ' + url)
        logger.debug('headers ' + str(headers))
        
        try:
            get_response = self.http.request("GET", url, None, headers)
            utils.check_response_500(get_response)
            logger.debug('get response status ' + str(get_response.status) + ': ' + str(get_response.reason))
        except http.client.BadStatusLine as exc:
            raise
        except http.client.HTTPException as exc:
            print((prog + f": error: request from {url} failed : {exc}"))
            raise
       
        return get_response
