"""Test cert-request script"""

import re
import sys
import unittest

from itertools import chain, permutations
from contextlib import contextmanager
from StringIO import StringIO

from osgpkitools import request

HOST = 'hostname.example.edu'
HOST_ARGS = [('--hostname', HOST)]
HOST_FILE = 'hosts.txt'
HOSTFILE_ARGS = [('--hostfile', HOST_FILE)]
LOCATION_ARGS = [('--country', 'US'),
                 ('--state', 'Wisconsin'),
                 ('--locality', 'Madison'),
                 ('--organization', 'University of Wisconsin - Madison')]


# Capture stdout/stderr from argparse from stack overflow:
# https://stackoverflow.com/questions/18651705/argparse-unit-tests-suppress-the-help-message
@contextmanager
def capture_sys_output():
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


def parse_cli(args):
    """Parse CLI args, flattening any tuples
    """
    if len(args) > 1:
        args = chain.from_iterable(args)
    request.parse_cli(args)


class CertRequestTests(unittest.TestCase):

    # def assertOption(self, sopt, lopt, dest, val):
    #     """Ensure that the hostfile is stored
    #     """
    #     try:
    #         parser = request.parse_cli([sopt, val])
    #     except SystemExit:
    #         pass

    #     try:
    #         lparser = request.parse_cli([lopt, val])
    #     except SystemExit:
    #         pass

    #     self.assertEqual(getattr(parser, dest), val, "{0} did not store {1} in the expected destination, {2}"
    #                      .format(sopt, val, dest))
    #     self.assertEqual(parser, lparser, "{0} and {1} are not the same".format(sopt, lopt))

    def test_conflicting_opts(self):
        """Users should not provide both a hostname and hosts file
        """
        with self.assertRaises(SystemExit) as cm:
            with capture_sys_output() as (stdout, stderr):
                parse_cli(HOST_ARGS + HOSTFILE_ARGS)
        self.assertEqual(cm.exception.code, 2, 'conflicting options did not exit 2')

    def test_required_opts(self):
        """Users need to provide location information and hostname or hosts file
        """
        for host in [[()], HOST_ARGS, HOSTFILE_ARGS]:
            for location in permutations(LOCATION_ARGS, 3):
                args = host + list(location)
                with self.assertRaises(SystemExit) as cm:
                    with capture_sys_output() as (stdout, stderr):
                        parse_cli(args)

                self.assertEqual(cm.exception.code, 2, "missing required options did not exit 2:\n{0}"
                                 .format(args))
                self.assert_(re.search(r'error.*is required.*', stderr.getvalue()))

    # def test_hostname_opt(self):
    #     """Ensure that the hostname is stored
    #     """
    #     self.assertOption('-H', '--hostname', 'hostname', HOST)

    # def test_hostfile_opt(self):
    #     """Ensure that the hostfile is stored
    #     """
    #     hfile = 'hosts.file'
    #     parser = request.parse_cli(['-F', hfile])
    #     lparser = request.parse_cli(['--hostfile', hfile])

    #     self.assertEqual(parser.hostfile, hfile, "-F did not store {0} to the expected destination, 'hostname'"
    #                      .format(hfile))
    #     self.assertEqual(parser, lparser, "-F and --hostfile are not the same")

    # def test_state_opt(self):
    #     self.fail

    # def test_country_opt(self):
    #     self.fail

    # def test_locality_opt(self):
    #     self.fail

    # def test_org_opt(self):
    #     self.fail

    def test_help_opt(self):
        """Verify help option
        """
        for opt in ['-h', '--help']:
            with self.assertRaises(SystemExit) as cm:
                with capture_sys_output() as (stdout, stderr):
                    parse_cli([opt])
            self.assertEqual(cm.exception.code, 0, '{0} did not exit 0'.format(opt))

    # def test_san_opt(self):
    #     """Ensure that SANs are stored as a list
    #     """
    #     sans = ['san1.example.edu', 'san2.example.edu', 'san3.example.edu']
    #     parser = request.parse_cli(HOST_ARGS + intersperse(sans, '-a'))
    #     self.assertListEqual(parser.altnames, sans, 'multiple SANs not stored as a list\n' +
    #                          'Arguments: {0}'.format(' '.join(sans)))

    #     lparser = request.parse_cli(HOST_ARGS + intersperse(sans, '--altname'))
    #     self.assertListEqual(lparser.altnames, sans, 'multiple SANs not stored as a list\n' +
    #                          'Arguments: {0}'.format(' '.join(sans)))


if __name__ == '__main__':
    unittest.main()
