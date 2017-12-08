"""Test cert-request script"""

import re
import unittest
from pkiunittest import OIM, DOMAIN, test_env_setup, test_env_teardown

class CertRequestTests(unittest.TestCase):

    def setUp(self):
        """Run each test in its own dir"""
        test_env_setup()

    def tearDown(self):
        """Remove personal test dir"""
        test_env_teardown()

    def test_help(self):
        """Verify help message"""
        for option in ('-h', '--help'):
            return_code, stdout, _, msg = OIM().request(option)
            self.assertEqual(return_code, 0, "Bad return code when requesting help\n%s" % msg)
            self.assert_(re.search(r'[Uu]sage:', stdout), msg)

    def test_required_opts(self):
        """Test required options"""
        # missing CSR/hostname
        return_code, _, _, msg = OIM().request('--phone', '1234567', '--email', 'foo@bar.com', '--name',
                                               'Foo Barrington')
        self.assertEqual(return_code, 2, "Missing CSR and hostname options did not fail\n%s" % msg)

        # missing phone number
        return_code, _, _, msg = OIM().request('--email', 'foo@bar.com', '--name', 'Foo Barrington', '--csr', 'csr_file')
        self.assertEqual(return_code, 2, "Missing phone option did not fail\n%s" % msg)

        # missing name
        return_code, _, _, msg = OIM().request('--phone', '1234567', '--email', 'foo@bar.com', '--csr', 'csr_file')
        self.assertEqual(return_code, 2, "Missing name option did not fail\n%s" % msg)

        # missing email
        return_code, _, _, msg = OIM().request('--phone', '1234567', '--name', 'Foo Barrington', '--csr', 'csr_file')
        self.assertEqual(return_code, 2, "Missing email option did not fail\n%s" % msg)

    def test_phone_validation(self):
        """Test valid phone numbers (r'[0-9-]*')
        """
        return_code, _, _, msg = OIM().request('--phone', '1234567')
        # rc should be 2 because we're missing required opts
        self.assertEqual(return_code, 2, "Did not accept only numbers\n%s" % msg)

        return_code, _, _, msg = OIM().request('--phone', '123-4567')
        # rc should be 2 because we're missing required opts
        self.assertEqual(return_code, 2, "Did not accept '-'\n%s" % msg)

        return_code, _, _, msg = OIM().request('--phone', "what's a phone number?")
        self.assertEqual(return_code, 2, "Invalid chars in phone number did not fail\n%s" % msg)

    def test_timeout_validation(self):
        """Test valid timeouts (>0)
        """
        return_code, _, _, msg = OIM().request('--timeout', '10')
        # rc should be 2 because we're missing required opts
        self.assertEqual(return_code, 2, "Did not accept timeout > 0\n%s" % msg)

        return_code, _, _, msg = OIM().request('--timeout', '0')
        # rc should be 2 because we're missing required opts
        self.assertEqual(return_code, 2, "Did not fail for timeout=0\n%s" % msg)

        return_code, _, _, msg = OIM().request('--timeout', '-5')
        # rc should be 2 because we're missing required opts
        self.assertEqual(return_code, 2, "Did not fail for timeout < 0\n%s" % msg)

        return_code, _, _, msg = OIM().request('--timeout', 'timeout')
        self.assertEqual(return_code, 2, "Did not fail on non-number\n%s" % msg)

    def test_arg_conflict(self):
        """Verify --csr and --hostname conflict"""
        oim = OIM()
        return_code, _, _, msg = oim.request('--hostname', 'test.' + DOMAIN, '--csr', 'foo')
        self.assertEqual(return_code, 2, "CSR and hostname options do not conflict\n%s" % msg)

    def test_cert_request(self):
        """Test making a request for a single host"""
        oim = OIM()
        return_code, _, _, msg = oim.request('--phone', '1234567', '--email', 'foo@bar.com', '--name',
                                             'Foo Barrington', '--hostname', 'test.' + DOMAIN)
        self.assertEqual(return_code, 0, "Failed to request certificate\n%s" % msg)
        self.assert_(oim.reqid != '', msg)

    def test_service_cert(self):
        """Test making a request for a service cert"""
        oim = OIM()
        return_code, _, _, msg = oim.request('--phone', '1234567', '--email', 'foo@bar.com', '--name',
                                             'Foo Barrington', '--hostname', 'service/test.' + DOMAIN)
        self.assertEqual(return_code, 0, "Failed to request certificate\n%s" % msg)
        self.assert_(oim.reqid != '', msg)

    def test_alt_name_request(self):
        """Test cert request with alternative name"""
        oim = OIM()
        hostname = 'test.' + DOMAIN
        san = 'test-san.' + DOMAIN
        san2 = 'test-san2.' + DOMAIN
        return_code, _, _, msg = oim.request('--phone', '1234567', '--email', 'foo@bar.com', '--name', 'Foo Barrington',
                                             '--hostname', hostname, '--altname', san, '--altname', san2)
        self.assertEqual(return_code, 0, "Failed to request certificate\n%s" % msg)
        self.assert_(oim.reqid != '', msg)

if __name__ == '__main__':
    unittest.main()
