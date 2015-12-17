"""Test the OSGPKIUtils module"""

import re
import sys

from PKIClientTestCase import PKIClientTestCase

# Allow import of OSGPKIUtilsTests. Hacky.
sys.path.insert(1, PKIClientTestCase.scripts_path) 
from OSGPKIUtils import Cert

class OSGPKIUtilsTests(PKIClientTestCase):
    fqdn = 'test.' + PKIClientTestCase.domain
    
    def __generate_csr(self, config):
        '''Helper for CSR generation'''
        test_cert = Cert()
        key_file = self.fqdn + '-key.pem'
        test_cert.CreatePKey(key_file)
        csr = test_cert.CreateX509Request(**config)
        self.assert_(csr, 'Could not create CSR')
        return csr
        
    def test_import(self):
        """Test osgpkitools.OSGPKIUtils import"""
        result = self.run_python("from osgpkitools.OSGPKIUtils import *")
        self.assertEqual(result.returncode, 0,
                         self.run_error_msg(result))

    def test_csr_generation(self):
        '''Generate a basic CSR'''
        config = {'CN': self.fqdn,
                  'emailAddress': self.email,
                  'alt_names': []}
        self.__generate_csr(config)
        
    def test_alt_name_csr_generation(self):
        '''Generate a CSR with multiple SANs'''
        alias = 'test-san.' + self.domain
        config = {'CN': self.fqdn,
                  'emailAddress': self.email,
                  'alt_names': [alias]}
        csr_contents = self.__generate_csr(config).as_text()
        self.assert_(re.search(r'X509v3 Subject Alternative Name: critical', csr_contents), 
                     "Subject Alternative Name not marked as 'critical'\n" + csr_contents)
        found_names = set(match.group(1) for match in re.finditer(r'DNS:([\w\-\.]+)', csr_contents))
        expected_names = set([alias])
        self.assertEqual(found_names, expected_names,
                         "Did not find expected SAN contents (%s):\n%s" %
                         (list(expected_names), csr_contents)) # printed lists are prettier than printed sets

if __name__ == '__main__':
    import unittest
    unittest.main()
