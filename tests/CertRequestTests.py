"""Test cert-request script"""

import re

import PKIClientTestCase

class CertRequestTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-cert-request"

    def test_help(self):
        """Test running with -h to get help"""
        env = self.get_test_env()
        result = self.run_script(env, self.command, "-h")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        # Python 2.4 optpase prints "usage" instead of "Usage"
        self.assertTrue("Usage:" in result.stdout or "usage:" in result.stdout,
                        err_msg)

    def test_request(self):
        """Test making a request"""
        env = self.get_test_env()
        fqdn = "test." + self.domain
        result = self.run_script(env,
                                 self.command,
                                 "--hostname", fqdn,
                                 "-e", self.email,
                                 "-n", self.name,
                                 "-p", self.phone)
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        match = re.search("^Request Id#: (\d+)\s*$",
                          result.stdout,
                          re.MULTILINE)
        self.assertNotEqual(match, None,
                            "Could not find request Id: " + err_msg)
        self.assertTrue(result.files_created.has_key("hostkey.pem"))
        # Check resulting key for looks
        key_file = "hostkey.pem"
        key_result = self.check_private_key(env, key_file)
        err_msg = self.run_error_msg(key_result)
        self.assertEqual(result.returncode, 0,
                         "Check of private key %s failed: %s" % (key_file,
                                                                 err_msg))

if __name__ == '__main__':
    import unittest
    unittest.main()
