"""Test osg-gridadmin-cert-request script"""

import PKIClientTestCase

class GridadminCertRequestTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-gridadmin-cert-request"

    def test_help(self):
        """Test running with -h to get help"""
        result = self.run_script(self.command, "-h")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        self.assertTrue("Usage:" in result.stdout, err_msg)
