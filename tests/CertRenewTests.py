"""Test osg-user-cert-renew script"""

import re
import unittest

from pkiunittest import OIM, test_env_setup, test_env_teardown

class CertRenewTests(unittest.TestCase):

    def setUp(self):
        """Run each test in its own dir"""
        test_env_setup()

    def tearDown(self):
        """Remove personal test dir"""
        test_env_teardown()

    def test_help(self):
        """Test running with -h to get help"""
        rc, stdout, _, msg = OIM().user_renew('--help')
        self.assertEqual(rc, 0, "Bad return code when requesting help\n%s" % msg)
        self.assert_(re.search(r'[Uu]sage:', stdout), msg)

    #TODO: Implement tests for actual renew functionality

if __name__ == '__main__':
    unittest.main()
