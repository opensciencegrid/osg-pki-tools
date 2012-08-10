#!/usr/bin/env python
"""Run tests on OSG PKI Command Line client scripts"""

import argparse
import getpass
import os
import os.path
import subprocess
import sys
import unittest

from PKIClientTestCase import PKIClientTestCase


def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
	argv = sys.argv

    # Argument parsing
    parser = argparse.ArgumentParser(
	description=__doc__, # printed with -h/--help
	# Don't mess with format of description
	formatter_class=argparse.ArgumentDefaultsHelpFormatter
	# To have --help print defaults with trade-off it changes
	# formatting, use: 
	)
    parser.add_argument("-c", "--certificate",
			default=PKIClientTestCase.get_user_cert_path(),
			help="Specific certificate for authentication",
			metavar="PATH")
    parser.add_argument("-p", "--privatekey",
			default=PKIClientTestCase.get_user_key_path(),
			help="Specific private key for authentication",
			metavar="PATH")
    parser.add_argument("-P", "--nopassphrase",
                        default=False,
                        action="store_const", const=True,
                        help="Do not prompt for pass phrase")
    parser.add_argument("-T", "--tests",
                        default="tests_*.py",
                        help="Specify tests to run",
                        metavar="GLOB")
    parser.add_argument("-v", "--verbose",
                        default=1,
                        action="store_const", const=2,
                        help="Run tests verbosely")

    args = parser.parse_args()

    # Store parameters so test cases can access them...
    PKIClientTestCase.set_user_cert_path(args.certificate)
    print "User certificate: " + PKIClientTestCase.get_user_cert_path()
    PKIClientTestCase.set_user_key_path(args.privatekey)
    print "User private key: " + PKIClientTestCase.get_user_key_path()

    if args.nopassphrase:
        pass_phrase = None
    else:
        pass_phrase = getpass.getpass(
            "Please enter pass phrase for private key (will not be echoed): ")
    PKIClientTestCase.set_user_key_pass_phrase(pass_phrase)

    loader = unittest.TestLoader()
    print "Running tests in " + args.tests
    suite = loader.discover(".", pattern=args.tests)

    #
    # Do it...
    runner = unittest.runner.TextTestRunner(verbosity=args.verbose)
    print "Running tests:"
    runner.run(suite)

    return(0)

if __name__ == "__main__":
    sys.exit(main())
