"""Test cert-request script"""

import PKIClientTestCase

class CertRequestTests(PKIClientTestCase.PKIClientTestCase):

    # TODO: Should be named cert-request-new to make DOE Grids scripts
    command = "HostCertRequest.py"

    def test_help(self):
        """Test running with -h to get help"""
        env = self.get_TestFileEnvironment()
        result = env.run(self.command, "-h")
        self.assertIn("usage:", result.stdout)
