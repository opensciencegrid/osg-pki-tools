"""Test the OSGPKIUtils module"""

import PKIClientTestCase

class  OSGPKIUtilsTests(PKIClientTestCase.PKIClientTestCase):

    def test_import(self):
        """Test 'from osgpkitools.OSGPKIUtils import *'"""
        result = self.run_python("from osgpkitools.OSGPKIUtils import *")
        self.assertEqual(result.returncode, 0,
                         self.run_error_msg(result))

if __name__ == '__main__':
    import unittest
    unittest.main()
