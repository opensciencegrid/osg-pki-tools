"""Test cert-retrieve script"""

import re
import unittest
from pkiunittest import OIM, DOMAIN, test_env_setup, test_env_teardown

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

    def test_retrieve(self):
        """Test retrieving a certificate"""
        oim = OIM()
        hostname = 'test.' + DOMAIN
        rc, _, _, msg = oim.request('--hostname', hostname)
        self.assertEqual(rc, 0, "Failed to request certificate\n%s" % msg)
        self.assert_(oim.reqid != '', msg)

    # TODO: Request cert, approve it (see osgpkiutils/ConnectAPI.py), and then retrieve it.

if __name__ == '__main__':
    unittest.main()
