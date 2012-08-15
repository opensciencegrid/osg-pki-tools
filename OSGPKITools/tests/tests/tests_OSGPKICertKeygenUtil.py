"""Test the OSGPKICertKeygenUtil module"""

import PKIClientTestCase

class  OSGPKICertKeygenUtilTests(PKIClientTestCase.PKIClientTestCase):

    def test_import(self):
        """Test 'from OSGPKICertKeygenUtil import *'"""
        result = self.run_python("from OSGPKICertKeygenUtil import *")
        self.assertEqual(result.returncode, 0,
                         self.run_error_msg(result))
