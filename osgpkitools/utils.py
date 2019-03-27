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

from ExceptionDefinitions import *

VERSION_NUMBER = "3.2.1"
HELP_EMAIL = 'help@opensciencegrid.org'


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
            print(exc)
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
