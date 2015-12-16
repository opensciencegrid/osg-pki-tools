"""Test cert-request script"""

import re
import unittest
from pkiunittest import OIM, DOMAIN, test_env_setup, test_env_teardown

class CertRequestTests(unittest.TestCase):

    def setUp(self):
        """Run each test in its own dir"""
        test_env_setup()

    def tearDown(self):
        """Remove personal test dir"""
        test_env_teardown()

    def test_help(self):
        """Run with -h to get help"""
        rc, stdout, _, msg = OIM().request('--help')
        self.assertEqual(rc, 0, "Bad return code when requesting help\n%s" % msg)
        self.assert_(re.search(r'[Uu]sage:', stdout), msg)
        
    def test_cert_request(self):
        """Test making a request for a single host"""
        oim = OIM()
        rc, _, _, msg = oim.request('--hostname', 'test.' + DOMAIN)
        self.assertEqual(rc, 0, "Failed to request certificate\n%s" % msg)
        self.assert_(oim.reqid != '', msg)

    def test_alt_name_request(self):
        """Test cert request with alternative name"""
        oim = OIM()
        hostname = 'test.' + DOMAIN
        san = 'test-san.' + DOMAIN
        san2 = 'test-san2.' + DOMAIN
        rc, _, _, msg = oim.request('--hostname', hostname,
                                    '--altname', san,
                                    '--altname', san2)
        self.assertEqual(rc, 0, "Failed to request certificate\n%s" % msg)
        self.assert_(oim.reqid != '', msg)

if __name__ == '__main__':
    unittest.main()
