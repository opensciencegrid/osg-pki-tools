"""Test cert-request script"""

import re
import sys
import unittest

from itertools import permutations
from contextlib import contextmanager
from StringIO import StringIO

from osgpkitools import cert_request`

HOST_ARGS = [('--hostname', 'hostname.example.edu')]
HOSTFILE_ARGS = [('--hostfile', 'hosts.txt')]
LOCATION_ARGS = [('--country', 'US'),
                 ('--state', 'New York'),
                 ('--locality', 'Stony Brook'),
                 ('--organization', 'SUNY - Stony Brook')]


# https://stackoverflow.com/questions/18651705/argparse-unit-tests-suppress-the-help-message
@contextmanager
def capture_sys_output():
    """Capture stdout/stderr from argparse from stack overflow.
    In addition to being able to compare stdout/stderr, it allows us to suppress them from the test output
    """
    capture_out, capture_err = StringIO(), StringIO()
    current_out, current_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = capture_out, capture_err
        yield capture_out, capture_err
    finally:
        sys.stdout, sys.stderr = current_out, current_err


def intersperse(lst, item):
    """Intersperse 'lst' with 'item'

    >>> intersperse([1, 2, 3], 0)
    [0, 1, 0, 2, 0, 3]
    """
    result = [item] * (len(lst) * 2)
    result[1::2] = lst
    return result


def parse_cli_flatten_args(args):
    """Parse CLI args, flattening any option/value tuples. We use tuples so that we can keep the options/values together
    when messing with the arg lists, e.g. itertools.permutations
    """
    args_list = []
    for arg in args:
        args_list.extend(arg)
    return request.parse_cli(args_list)


class CertRequestTests(unittest.TestCase):
    """Tests for CSR generation
    """

    def test_conflicting_opts(self):
        """Users should not provide both a hostname and hosts file
        """
        with capture_sys_output() as (_, _):
            self.assertRaises(SystemExit, parse_cli_flatten_args, HOST_ARGS + HOSTFILE_ARGS)

    def test_required_opts(self):
        """Users need to provide location information and hostname or hosts file
        """
        for host in [[()], HOST_ARGS, HOSTFILE_ARGS]:
            for location in permutations(LOCATION_ARGS, 3):
                args = host + list(location)
                with capture_sys_output() as (_, stderr):
                    self.assertRaises(SystemExit, parse_cli_flatten_args, args)

                self.assert_(re.search(r'error.*is required.*', stderr.getvalue()))

    def test_ignored_opts(self):
        """-A/--altname should be ignored when specifying -F/--hostfile
        """
        with capture_sys_output() as (_, _):
            args = parse_cli_flatten_args(HOSTFILE_ARGS + LOCATION_ARGS +
                                          [('--altname', 'test-san.opensciencegrid.org')])
        self.assertEqual(args.altnames, [], 'Altname option was not ignored when --hostfile was specified')

    def test_state_opt(self):
        """State values should be unabbreviated
        """
        with capture_sys_output() as (_, _):
            self.assertRaises(ValueError, parse_cli_flatten_args, HOST_ARGS + [('--state', 'WI')])

        args = parse_cli_flatten_args(HOST_ARGS + LOCATION_ARGS)
        self.assertEqual(args.state, 'New York', "Unexpected value '{0}' for state option:\n{1}".
                         format(args.state, args))

    def test_country_opt(self):
        """Country values should be the abbreviated, 2-letter country code
        """
        with capture_sys_output() as (_, _):
            self.assertRaises(ValueError, parse_cli_flatten_args, HOST_ARGS + [('--country', 'United States')])

        args = parse_cli_flatten_args(HOST_ARGS + LOCATION_ARGS)
        self.assertEqual(args.country, 'US', "Unexpected value '{0}' for country option:\n{1}".
                         format(args.country, args))

    def test_help_opt(self):
        """Verify help option
        """
        for opt in ['-h', '--help']:
            with capture_sys_output() as (_, _):
                self.assertRaises(SystemExit, parse_cli_flatten_args, [opt])


if __name__ == '__main__':
    unittest.main()
