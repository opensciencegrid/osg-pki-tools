"""Test osg-user-cert-renew script"""

import PKIClientTestCase


class CertRetrieveTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-user-cert-renew"

    def test_help(self):
        """Test running with -h to get help"""
        env = self.get_test_env()
        result = self.run_script(env, self.command, "-h")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        # Python 2.4 optpase prints "usage" instead of "Usage"
        self.assertTrue("Usage:" in result.stdout or "usage:" in result.stdout,
                        err_msg)

if __name__ == '__main__':
    import unittest
    unittest.main()
