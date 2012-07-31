"""Test cert-request script"""

import PKIClientTestCase

class CertRequestTests(PKIClientTestCase.PKIClientTestCase):

    command = "cert-request-new.py"

    def test_help(self):
        """Test running with -h to get help"""
        env = self.get_TestFileEnvironment()
        result = env.run("python", self.command, "-h")
        self.assertIn("Usage:", result.stdout)
