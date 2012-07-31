#!/usr/bin/env python
"""Run tests on OSG PKI Command Line client scripts"""

import getpass
import optparse
import os
import os.path
import subprocess
import sys
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from PKIClientTestCase import PKIClientTestCase


def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
	argv = sys.argv

    # Argument parsing
    parser = optparse.OptionParser()
    parser.add_option("-c", "--certificate",
                      default=PKIClientTestCase.get_user_cert_path(),
                      help="Specific certificate for authentication",
                      metavar="PATH")
    parser.add_option("-p", "--privatekey",
                      default=PKIClientTestCase.get_user_key_path(),
                      help="Specific private key for authentication",
                      metavar="PATH")
    parser.add_option("-P", "--nopassphrase",
                      default=False,
                      action="store_const", const=True,
                      help="Do not prompt for pass phrase")
    parser.add_option("-T", "--tests",
                      default="tests_*.py",
                      help="Specify tests to run",
                      metavar="GLOB")
    parser.add_option("-v", "--verbose",
                      default=1,
                      action="store_const", const=2,
                      help="Run tests verbosely")

    (options, args) = parser.parse_args()

    # Store parameters so test cases can access them...
    PKIClientTestCase.set_user_cert_path(options.certificate)
    print "User certificate: " + PKIClientTestCase.get_user_cert_path()
    PKIClientTestCase.set_user_key_path(options.privatekey)
    print "User private key: " + PKIClientTestCase.get_user_key_path()

    if options.nopassphrase:
        pass_phrase = None
    else:
        pass_phrase = getpass.getpass(
            "Please enter pass phrase for private key (will not be echoed): ")
    PKIClientTestCase.set_user_key_pass_phrase(pass_phrase)

    loader = unittest.TestLoader()
    print "Running tests in " + options.tests
    suite = loader.discover(".", pattern=options.tests)

    #
    # Do it...
    runner = unittest.runner.TextTestRunner(verbosity=options.verbose)
    print "Running tests:"
    runner.run(suite)

    return(0)

if __name__ == "__main__":
    sys.exit(main())
