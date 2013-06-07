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
        # 83 is a known good certificate but otherwise arbitrary
        # Cert 83 is for: tinge.hpcc.ttu.edu (099CA8A28EC4496A2644A78C5F1DFDCD)
        env = self.get_test_env()
        result = self.run_script(env, self.command, "-i", "83")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        # Make sure certificate looks OK
        self.assertTrue(result.files_created.has_key("hostcert.pem"),
                        "Cannot find retrieved certificate\n" + err_msg)
        cert_file = "hostcert.pem"
        cert_result = self.check_certificate(env, cert_file)
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0,
                         "Failed checking certificate %s: %s" % (cert_file,
                                                                 err_msg))

    def test_retrieve_duplication(self):
        """Test retrieving a certificate with existing file"""
        # 83 is a known good certificate but otherwise arbitrary
        # Cert 83 is for: tinge.hpcc.ttu.edu (099CA8A28EC4496A2644A78C5F1DFDCD)
        env = self.get_test_env()
        result = self.run_script(env, self.command, "-i", "83")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        self.assertTrue(result.files_created.has_key("hostcert.pem"),
                        "Cannot find retrieve certificate\n" + err_msg)
        # Now get a second certificate, which should cause first to be renamed
        result = self.run_script(env, self.command, "-i", "83")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        # Make sure we see moved aside certificate
        # (Note that result won't have hostcert.pem as created because it
        #  already existed)
        self.assertTrue(result.files_created.has_key("hostcert-old.pem"),
                        "Cannot find renamed certificate\n" + err_msg)

if __name__ == '__main__':
    import unittest
    unittest.main()
