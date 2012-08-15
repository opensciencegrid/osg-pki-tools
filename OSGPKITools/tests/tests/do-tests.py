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
                      default=PKIClientTestCase.get_cert_path(),
                      help="Specify certificate for authentication",
                      metavar="PATH")
    parser.add_option("-p", "--privatekey",
                      default=PKIClientTestCase.get_key_path(),
                      help="Specify private key for authentication",
                      metavar="PATH")
    parser.add_option("-s", "--scripts-path",
                      default="..",
                      help="Specify path to scripts",
                      metavar="PATH")
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
    PKIClientTestCase.set_cert_path(options.certificate)
    print "Test certificate: " + PKIClientTestCase.get_cert_path()
    PKIClientTestCase.set_key_path(options.privatekey)
    print "Test private key: " + PKIClientTestCase.get_key_path()
    PKIClientTestCase.set_scripts_path(options.scripts_path)
    print "Path to scripts: " + PKIClientTestCase.get_scripts_path()

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
