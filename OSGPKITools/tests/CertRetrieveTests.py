"""Test cert-retrieve script"""

import PKIClientTestCase

class CertRetrieveTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-cert-retrieve"

    def test_help(self):
        """Test running with -h to get help"""
        env = self.get_test_env()
        result = self.run_script(env, self.command, "-h")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        # Python 2.4 optpase prints "usage" instead of "Usage"
        self.assertTrue("Usage:" in result.stdout or "usage:" in result.stdout,
                        err_msg)

    def test_retrieve(self):
        """Test retrieving a certificate"""
        # 90 is a known good certificate but otherwise arbitrary
        env = self.get_test_env()
        result = self.run_script(env, self.command, "-i", "90")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        # Make sure certificate looks OK
        self.assertTrue(result.files_created.has_key("host-cert.pem"),
                        "Cannot find retrieve certificate\n" + err_msg)
        cert_file = "host-cert.pem"
        cert_result = self.check_certificate(env, cert_file)
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0,
                         "Failed checking certificate %s: %s" % (cert_file,
                                                                 err_msg))

if __name__ == '__main__':
    import unittest
    unittest.main()
