"""Test cert-retrieve script"""

import PKIClientTestCase

class CertRetrieveTests(PKIClientTestCase.PKIClientTestCase):

    # TODO: Should be named cert-retrieve-new to make DOE Grids scripts
    command = "RetrieveCert.py"

    def test_help(self):
        """Test running with -h to get help"""
        env = self.get_TestFileEnvironment()
        result = env.run(self.command, "-h")
        self.assertIn("usage:", result.stdout)
