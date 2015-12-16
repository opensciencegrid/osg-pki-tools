"""Test osg-user-cert-revoke script"""

import re
import unittest
from pkiunittest import OIM, DOMAIN, test_env_setup, test_env_teardown

class CertRevokeTests(unittest.TestCase):

    def setUp(self):
        """Run each test in its own dir"""
        test_env_setup()

    def tearDown(self):
        """Remove personal test dir"""
        test_env_teardown()
    
    def test_help(self):
        """Test running with -h to get help"""
        rc, stdout, _, msg = OIM().revoke('--help')
        self.assertEqual(rc, 0, "Bad return code when requesting help\n%s" % msg)        
        self.assert_(re.search(r'[Uu]sage:', stdout), msg)

    def test_user_help(self):
        """Test running with -h to get help"""
        rc, stdout, _, msg = OIM().user_revoke('--help')
        self.assertEqual(rc, 0, "Bad return code when requesting help\n%s" % msg)        
        self.assert_(re.search(r'[Uu]sage:', stdout), msg)
        
    def test_revoke(self):
        """Test basic revocation"""
        request = OIM()
        rc, _, _, msg = request.gridadmin_request('--hostname', 'test.' + DOMAIN)
        self.assertEqual(rc, 0, "Failed to request certificate\n%s" % msg)
        rc, stdout, _, msg = request.revoke()
        self.assertEqual(rc, 0, "Failed to revoke certificate\n%s" % msg)
        print stdout

if __name__ == '__main__':
    unittest.main()
