"""Test osg-gridadmin-cert-request script"""

import PKIClientTestCase

class GridadminCertRequestTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-gridadmin-cert-request"

    def test_help(self):
        """Test running with -h to get help"""
        result = self.run_script(self.command, "-h")
        self.assertTrue("Usage:" in result.stdout,
                        self.run_error_msg(result))
