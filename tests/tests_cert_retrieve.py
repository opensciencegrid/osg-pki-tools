"""Test cert-retrieve script"""

import PKIClientTestCase

class CertRetrieveTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-cert-retrieve"

    def test_help(self):
        """Test running with -h to get help"""
        result = self.run_script(self.command, "-h")
        self.assertTrue("Usage:" in result.stdout,
                        self.run_error_msg(result))

    def test_retrieve(self):
        """Test retrieving a certificate"""
        # 90 is a known good certificate but otherwise arbitrary
        result = self.run_script(self.command, "-i", "90")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        self.assertTrue("Certificate written to" in result.stdout, err_msg)
