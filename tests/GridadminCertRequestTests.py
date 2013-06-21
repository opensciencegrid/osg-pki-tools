"""Test osg-gridadmin-cert-request script"""

import os.path
import re

import PKIClientTestCase

class GridadminCertRequestTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-gridadmin-cert-request"

    def test_help(self):
        """Test running with -h to get help"""
        env = self.get_test_env()
        result = self.run_script(env, self.command, "-h")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        # Python 2.4 optpase prints "usage" instead of "Usage"
        self.assertTrue("Usage:" in result.stdout or "usage:" in result.stdout,
                        err_msg)

    def test_no_args(self):
        """Test running without arguments and seeing usage"""
        env = self.get_test_env()
        result = self.run_script(env, self.command)
        err_msg = self.run_error_msg(result)
        self.assertNotEqual(result.returncode, 0, err_msg)
        # Python 2.4 optpase prints "usage" instead of "Usage"
        # Reverting back to stderr from revision 17059
        self.assertTrue("Usage:" in result.stderr or "usage:" in result.stderr,
                        err_msg)

if __name__ == '__main__':
    import unittest
    unittest.main()
