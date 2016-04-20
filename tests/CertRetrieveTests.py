"""Test cert-retrieve script"""

import re
import unittest
from pkiunittest import OIM, test_env_setup, test_env_teardown

class CertRetrieveTests(unittest.TestCase):

    def setUp(self):
        """Run each test in its own dir"""
        test_env_setup()

    def tearDown(self):
        """Remove personal test dir"""
        test_env_teardown()

    def test_help(self):
        """Run with -h to get help"""
        rc, stdout, _, msg = OIM().retrieve('--help')
        self.assertEqual(rc, 0, "Bad return code when requesting help\n%s" % msg)
        self.assert_(re.search(r'[Uu]sage:', stdout), msg)

    def test_timeout_bad_input(self):
        """Ensure tool fails on negative int input"""
        oim = OIM()
        oim.reqid = '1' # avoid missing reqid argument check
        rc, _, _, msg = oim.retrieve('--timeout', '-1')
        self.assertEqual(rc, 1, 'Succeeded on negative int input\n%s' % msg)

        rc, _, _, msg = oim.retrieve('--timeout', 'string')
        self.assertEqual(rc, 1, 'Succeeded on string input\n%s' % msg)

    # TODO: Request cert, approve it (see osgpkiutils/ConnectAPI.py), and then retrieve it.

if __name__ == '__main__':
    unittest.main()
