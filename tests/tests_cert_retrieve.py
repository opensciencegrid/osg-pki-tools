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
        self.assertTrue("Usage:" in result.stdout, err_msg)

    def test_retrieve(self):
        """Test retrieving a certificate"""
        # 90 is a known good certificate but otherwise arbitrary
        env = self.get_test_env()
        result = self.run_script(env, self.command, "-i", "90")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        # Make sure certificate looks OK
        result = env.run("openssl", "x509",
                         "-in", "hostcert.pem")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
