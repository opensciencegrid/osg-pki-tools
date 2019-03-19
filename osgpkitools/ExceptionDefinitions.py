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
