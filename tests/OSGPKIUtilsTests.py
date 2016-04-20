"""Test the OSGPKIUtils module"""

import re
import signal
import sys
import unittest

from pkiunittest import DOMAIN, EMAIL, PYPATH

# Allow import of OSGPKIUtilsTests. Hacky.
sys.path.insert(1, PYPATH)
from osgpkitools import OSGPKIUtils

class OSGPKIUtilsTests(unittest.TestCase):
    FQDN = 'test.' + DOMAIN
    
    def __generate_csr(self, config):
        '''Helper for CSR generation'''
        test_cert = OSGPKIUtils.Cert()
        key_file = self.FQDN + '-key.pem'
        test_cert.CreatePKey(key_file)
        csr = test_cert.CreateX509Request(**config)
        self.assert_(csr, 'Could not create CSR')
        return csr
        
    def test_csr_generation(self):
        '''Generate a basic CSR'''
        config = {'CN': self.FQDN,
                  'emailAddress': EMAIL,
                  'alt_names': []}
        self.__generate_csr(config)
        
    def test_alt_name_csr_generation(self):
        '''Generate a CSR with multiple SANs'''
        alias = 'test-san.' + DOMAIN
        config = {'CN': self.FQDN,
                  'emailAddress': EMAIL,
                  'alt_names': [alias]}
        csr_contents = self.__generate_csr(config).as_text()
        self.assert_(re.search(r'X509v3 Subject Alternative Name: critical', csr_contents), 
                     "Subject Alternative Name not marked as 'critical'\n" + csr_contents)
        found_names = set(match.group(1) for match in re.finditer(r'DNS:([\w\-\.]+)', csr_contents))
        expected_names = set([alias])
        self.assertEqual(found_names, expected_names,
                         "Did not find expected SAN contents (%s):\n%s" %
                         (list(expected_names), csr_contents)) # printed lists are easier to read` than printed sets

    def test_timeout(self):
        '''Verify timeout length'''
        OSGPKIUtils.start_timeout_clock(1) # 1 minute timeout
        alarm_timer = signal.alarm(0) # cancel alarm and get remaining time of previous alarm
        self.assertEqual(alarm_timer, 60, 'Expected 1 min timeout, got %ss' % alarm_timer)

    def test_sigalrm_handler(self):
        '''Verify exiting handler'''
        self.assertRaises(SystemExit, OSGPKIUtils.start_timeout_clock, 0)

if __name__ == '__main__':
    unittest.main()
