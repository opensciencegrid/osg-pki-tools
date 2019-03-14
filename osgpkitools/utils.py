#!/usr/bin/python

from __future__ import print_function
import ConfigParser
import errno
import os
import shutil
import sys
import tempfile
import textwrap
import json
import traceback
import getpass
from StringIO import StringIO
from M2Crypto import SSL, m2, RSA, EVP, X509

from ExceptionDefinitions import *

VERSION_NUMBER = "3.1.0"
HELP_EMAIL = 'help@opensciencegrid.org'


def charlimit_textwrap(string):
    """This function wraps up the output to 80 characters. Accepts string and print the wrapped output"""

    list_string = textwrap.wrap(str(string), width=80)
    for line in list_string:
        print(line)
    return


def print_exception_message(exc):
    """Checks if the str representation of the exception is empty or not
    if empty, it prints an generic error message stating the type of exception
    and traceback.
    """

    if str(exc) != "":
        charlimit_textwrap("Got an exception %s" % exc.__class__.__name__)
        charlimit_textwrap(exc)
        #charlimit_textwrap('Please report the bug to %s.' % HELP_EMAIL)
    else:
        handle_empty_exceptions(exc)


def handle_empty_exceptions(exc):
    """The method handles all empty exceptions and displays a meaningful message and
    traceback for such exceptions."""

    print(traceback.format_exc())
    charlimit_textwrap('Encountered exception of type %s' % exc.__class__.__name__)
    #charlimit_textwrap('Please report the bug to %s.' % HELP_EMAIL)


def format_csr(csr):
    """Extract the base64 encoded string from the contents of a CSR"""
    return csr.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '')\
              .replace('-----END CERTIFICATE REQUEST-----\n', '')\
              .replace('\n', '')


def atomic_write(filename, contents):
    """Write to a temporary file then move it to its final location
    """
    temp_fd, temp_name = tempfile.mkstemp(dir=os.path.dirname(filename))
    os.write(temp_fd, contents)
    os.close(temp_fd)
    os.rename(temp_name, filename)


def check_response_500(response):
    """ This functions handles the 500 error response from the server"""

    if response.status == 500:
        raise Exception_500response(response.status, response.reason)


def safe_rename(filename):
    """Renames 'filename' to 'filename.old'
    """
    old_filename = filename + '.old'
    try:
        shutil.move(filename, old_filename)
        print("Renamed existing file from %s to %s" % (filename, old_filename))
    except IOError, exc:
        if exc.errno != errno.ENOENT:
            charlimit_textwrap(exc)
            raise RuntimeError('ERROR: Failed to rename %s to %s' % (filename, old_filename))


def safe_write(filename, contents):
    """Safely backup the target 'filename' then write 'contents'
    """
    safe_rename(filename)
    atomic_write(filename, contents)

def check_permissions(path):
    """The function checks for write permissions for the given path to verify if the user has write permissions
    """
    if os.access(path, os.W_OK):
        return
    else:
        raise FileWriteException("User does not have appropriate permissions for writing to " + path)


def verify_user_cred(usercert, userkey):
    """Verify the  readable user cert/key pair
    INPUT
        usercert: path to user certificate 
        userkey: path to private key of user 
    OUTPUT 
        Paths to the verified user cert and key 
    """

    cert = os.path.expanduser(usercert)
    key = os.path.expanduser(userkey)
    
    # M2Crypto doesn't raise exceptions when encountering missing or unreadable
    # cert/key pair so we force the issue

    try:
        open(cert, 'r')
        open(key, 'r')
        return cert, key
    except IOError:
        raise IOError("Unable to read the certificate/key pair at:  %s" % cert + " " + key)


def print_failure_reason_exit(data):
    """This functions prints the failure reasons and exits"""
    try:
        msg = 'The request has failed for the following reason: %s' % \
        json.loads(data)['detail'].split('--')[1].lstrip()
    except IndexError:
        msg = 'The request has failed for the following reason: %s' % json.loads(data)['detail'].lstrip() + \
              'Status : %s ' % json.loads(data)['status']

    separator = '='*80
    sys.exit('\n'.join(textwrap.wrap(separator + msg, width=80)))

