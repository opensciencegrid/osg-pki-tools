"""Test cert-retrieve script"""

import PKIClientTestCase

class CertRetrieveTests(PKIClientTestCase.PKIClientTestCase):

    command = "cert-retrieve-new.py"

    def test_help(self):
        """Test running with -h to get help"""
        result = self.run_script(self.command, "-h")
        self.assertTrue("Usage:" in result.stdout)
