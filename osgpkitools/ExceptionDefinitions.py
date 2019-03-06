""" This script contains all the exception classes and would be exclusively used for handling exceptions"""


class Exception_500response(Exception):
    """Exception raised for 500 response.

    Attributes:
        status -- Status of the response
        message -- explanation of the error
    """

    def __init__(self, status, message):
        self.status = status
        self.message = message

    def __str__(self):
        return str(self.message)


class FileNotFoundException(Exception):
    """ Exception raised when a file is not found

    Attributes:
        filename -- Name of the file that is not found
        message -- message to be printed for this exception
        """

    def __init__(self, filename, message):
        self.filename = filename
        self.message = message

    def __str__(self):
        return str(self.message)


class NotOKException(Exception):
    """Exception raised when OK string is not found and is expected in response

    Attributes:
        status -- Status of the response
        message -- message of the failure reponse
        """

    def __init__(self, status, message):
        self.status = status
        self.message = message

    def __str__(self):
        return "OK not found; status: %s; reason: %s" % (self.status, self.message)


class UnexpectedBehaviourException(Exception):
    """Exception raised when and unexpected behaviour of the CLI script is encountered.
    This is different from Uncaught Exception. Here we expect for example a string like OK
    and is not present.

    Attributes:
        message -- Message to be displayed
        """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class CertificateMismatchException(Exception):
    """Exception occurs when the requested number of certificate does not match with the
    retrieved number of certificates. Applicable for Bulk certificate request primarily.

    Attributes:
        request_num -- no. of requested certificates
        retrieve_num -- no. of retrieved certificates
        message -- message to be displayed
    """

    def __init__(self, request_num, retrieve_num, message):
        self.request_num = request_num
        self.retrieve_num = retrieve_num
        self.message = message

    def __str__(self):
        return str(self.message)


class BadCertificateException(Exception):
    """Exception occurs when a certificate is not trusted by the server.

    Attributes:
        message -- message to be displayed
        """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class BadPassphraseException(Exception):
    """ This Exception occurs when the passphrase entered for the private key file
    does not match the stored passphrase of the key file.

    Attributes:
        message -- message to be displayed
        """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class HandshakeFailureException(Exception):
    """This exception occurs for a failure for valid key/cert pair

    Attributes:
        message -- message to be displayed
        """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class ValidationException(Exception):
    """Exception occurs when validation fails
    Attributes:
        message = message to be displayed"""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class InvalidOptionException(Exception):
    """This exception occurs when and invalid option is selected

    Attributes:
        message = message to be displayed"""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class NotApprovedException(Exception):
    """This exception occurs when the retrieval script tries to retrieve a certificate whose
    request is in Requested state and has not been Approved.

    Attributes:
        message = message to be displayed"""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class InsufficientArgumentException(Exception):
    """This exception is raised when insufficient number of arguments are passed to a script."""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class FileWriteException(Exception):
    """This exception is raised when the user does not have permission to write in the current directory"""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class AuthenticationFailureException(Exception):
    """This exception is raised when the credentials provided by the user are invalid"""

    def __init__(self, status, message):
        self.status = status
        self.message = message

    def __str__(self):
        return str(self.message)

 
class ConnectionFailureException(Exception):
    """This exception is raised when the connection failed due to an invalid url or a timeout"""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)
