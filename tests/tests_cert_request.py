"""Test cert-request script"""

import PKIClientTestCase

class CertRequestTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-cert-request"

    def test_help(self):
        """Test running with -h to get help"""
        result = self.run_script(self.command, "-h")
        self.assertTrue("Usage:" in result.stdout,
                        self.run_error_msg(result))

    def test_request(self):
        """Test making a request"""
        result = self.run_script(self.command,
                                 # TODO: Good hostname for testing?
                                 "--hostname", "test.bw.iu.edu",
                                 "-e", self.email,
                                 "-n", self.name,
                                 "-p", self.phone)
        self.assertEqual(result.returncode, 0,
                         self.run_error_msg(result))
