"""Test cert-retrieve script"""

import PKIClientTestCase

class CertRetrieveTests(PKIClientTestCase.PKIClientTestCase):

    command = "cert-retrieve-new.py"

    def test_help(self):
        """Test running with -h to get help"""
        env = self.get_TestFileEnvironment()
        result = env.run("python", self.command, "-h")
        self.assertTrue("Usage:" in result.stdout)
