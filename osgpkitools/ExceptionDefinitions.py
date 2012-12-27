""" This script ontains all the exception classes and would be exclusively used for handling exceptions"""

class Exception_500response(Exception):
    """Exception raised for 500 response.

    Attributes:
        status -- Status of the response 
        message -- explanation of the error
    """

    def __init__(self, status, message):
        self.status = status
        self.message = message
        
class TimeoutException(Exception):
    """ Exception raised for all timeouts
    
    Attributes:
        timeout -- timeout limit set after which the exception took place
        """
    def __init__(self,timeout):
        self.timeout = timeout

class FileNotFoundException(Exception):
    """ Exception raised when a file is not found
    
    Attributes:
        filename -- Name of the file that is not found
        message -- message to be printed for this exception
        """
    def __init__(self,filename, message):
        self.filename = filename
        self.message = message
        
class NotOKException(Exception):
    """Exception raised when OK string is not found and is expected in response
    
    Attributes:
        status -- Status of the response
        reason -- reason of the failure reponse
        """
    def __init (self,status,reason):
        self.status = status
        self.reason = reason

class UnexpectedBehaviourException(Exception):
    """Exception raised when and unexpected behaviour of the CLI script is encountered.\
    This is different from Uncaught Exception. Here we expect for example a string like OK\
    and is not present.
    
    Attributes:
        message -- Message to be displayed
        """
    def __init__(self,message):
        self.message = message
        
class CertificateMismatchException(Exception):
    """Exception occurs when the requested number of certificate does not match with the\
    retrieved number of certificates. Applicable for Bulk certificate request primarily.
    
    Attributes:
        request_num -- no. of requested certificates
        retrieve_num -- no. of retrieved certificates
        message -- message to be displayed
    """
    
    def __init__(self, request_num, retrieve_num, message):
        self.request_um = request_num
        self.retrieve_num - retrieve_num
        self.message = message
        
class BadCertificateException(Exception):
    """Execption occurs when a certificate is not trusted by the server.
    
    Attributes:
        message -- message to be displayed
        """
    def __init__(self,message):
        self.message = message
        
class BadPassphraseException(Exception):
    """ This Exception occurs when the passphrase entered for the private key file\
    does not match the stored passphrase of the key file.
    
    Attributes:
        message -- message to be displayed
        """
    def __init__(self, message):
        self.message = message
        
class HandshakeFailureException(Exception):
    """This exception occurs for a failure for valid key/cert pair
    
    Attributes:
        message -- message to be displayed
        """
    def __init__(self,message):
        self.message = message
        
class UncaughtException(Exception):
    """This exception is called when any uncaught exception occurs
    
    Attributes:
        message = message to be displayed"""
        
    def __init__(self,message):
        self.message = message
        
class QuotaException(Exception):
    """This exception occurs when the approval quota of the user is predicted to be exceeded\
    in the current request.
    
    Attributes:
        message = message to be displayed"""
        
    def __init__(self,message):
        self.message = message
    
class ValidationException(Exception):
    """Exception occurs when validation fails
    Attributes:
        message = message to be displayed"""
        
    def __init__(self,message):
        self.message = message

class InvalidOptionException(Exception):
    """This exception occurs when and invalid option is selected
    
    Attributes:
        message = message to be displayed"""
        
    def __init__(self,message):
        self.message = message

class NotApprovedException(Exception):
    """This exception occurs when the retrieval script tries to retrieve a certificate whose \
    request is in Requested state and has not been Approved.
    
    Attributes:
        message = message to be displayed"""
        
    def __init__(self,message):
        self.message = message
