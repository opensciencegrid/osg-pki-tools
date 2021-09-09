"""Test the OSGPKIUtils module"""

import re
import signal
from json import dumps
import sys
import unittest

from .pkiunittest import DOMAIN, EMAIL, PYPATH

# Allow import of OSGPKIUtilsTests. Hacky.
sys.path.insert(1, PYPATH)
from osgpkitools import OSGPKIUtils

class OSGPKIUtilsTests(unittest.TestCase):
    FQDN = 'test.' + DOMAIN

    def test_csr_generation(self):
        '''Generate a basic CSR'''
        cert = OSGPKIUtils.Cert(self.FQDN, email=EMAIL)
        self.assertTrue(cert.x509request, 'missing CSR contents')

    def test_alt_name_csr_generation(self):
        '''Generate a CSR with multiple SANs'''
        alias = 'test-san.' + DOMAIN
        cert = OSGPKIUtils.Cert(self.FQDN, altnames=[alias], email=EMAIL)
        csr_contents = cert.x509request.as_text()
        self.assertIsNotNone(re.search(r'X509v3 Subject Alternative Name: critical', csr_contents),
                     "Subject Alternative Name not marked as 'critical'\n" + csr_contents)
        found_names = set(match.group(1) for match in re.finditer(r'DNS:([\w\-\.]+)', csr_contents))
        expected_names = set([alias])
        self.assertEqual(found_names, expected_names,
                         f"Did not find expected SAN contents {list(expected_names)}:\n{csr_contents}") # printed lists are easier to read` than printed sets

    def test_timeout(self):
        '''Verify timeout length'''
        OSGPKIUtils.start_timeout_clock(1) # 1 minute timeout
        alarm_timer = signal.alarm(0) # cancel alarm and get remaining time of previous alarm
        self.assertEqual(alarm_timer, 60, f'Expected 1 min timeout, got {alarm_timer}s')

    def test_sigalrm_handler(self):
        '''Verify exiting handler'''
        self.assertRaises(SystemExit, OSGPKIUtils.start_timeout_clock, 0)

    def test_missing_vo_exception(self):
        '''Verify helpful error message when user fails to include necessary VO information.'''
        response = dumps({'status': 'FAILED',
                          'detail': ' -- '.join(["Failed to find GridAdmins for specified CSRs/VO",
                                                 "Couldn't find GridAdmin group under specified VO.",
                                                 "GOC alert will be sent to GOC infrastructure team about this " + \
                                                 "issue. Meanwhile, feel free to open a GOC ticket at " + \
                                                 "https://ticket.grid.iu.edu"])})
        try:
            OSGPKIUtils.print_failure_reason_exit(response)
        except SystemExit:
            pass
        else:
            self.fail("print_failure_reason_exit() did not raise SystemExit")

    def test_read_config(self):
        '''Verify that configuration is read in as a dictionary'''
        for section, itb in list({'production': False, 'ITB': True}.items()):
            self.assertTrue(OSGPKIUtils.read_config(itb, config_files=['../osgpkitools/pki-clients.ini']),
                         f'Unable to read the {section} config section')



if __name__ == '__main__':
    unittest.main()
