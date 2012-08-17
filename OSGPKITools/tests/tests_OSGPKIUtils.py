"""Test the OSGPKIUtils module"""

import PKIClientTestCase

class  OSGPKIUtilsTests(PKIClientTestCase.PKIClientTestCase):

    def test_import(self):
        """Test 'from OSGPKIUtils import *'"""
        result = self.run_python("from OSGPKIUtils import *")
        self.assertEqual(result.returncode, 0,
                         self.run_error_msg(result))
