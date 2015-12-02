"""Test cert request and revocation for a single host as a GridAdmin"""

import re

from PKIClientTestCase import PKIClientTestCase

class GridadminCertSingleHostRequestAndRevocationTests(PKIClientTestCase):

    command = "osg-gridadmin-cert-request"
    command_revoke = "osg-cert-revoke"
    fqdn = "test." + PKIClientTestCase.domain

    request_args = ["--hostname", fqdn,
                    "--pkey", PKIClientTestCase.get_key_path(),
                    "--cert", PKIClientTestCase.get_cert_path()]

    def run_gridadmin_script(self, command, *args, **kwargs):
        """Set up environment for GridAdmin script and verify the return code (0 by default)"""
        rc = 0
        if kwargs.has_key('rc'):
            rc = kwargs['rc']

        env = self.get_test_env()
        result = self.run_script(env, command, *args)
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, rc, err_msg)
        return (env, result, err_msg)

    def request_and_revoke_cert(self, *args):
        """Request and revoke a cert, verifying successful interaction with OIM"""
        env, result, err_msg = self.run_gridadmin_script(self.command, *args)
        match = re.search(r"^Id is: (\d+)\s*$",
                          result.stdout,
                          re.MULTILINE)
        self.assert_(match,"Could not find request Id: " + err_msg)
        request_id = int(match.group(1))


        match = re.search("Certificate written to (.*)$",
                          result.stdout,
                          re.MULTILINE)
        self.assert_(match, "Could not find output certificate: " + err_msg)
        cert_file = match.group(1)

        # Check output certificate
        cert_result = self.check_certificate(env, cert_file)
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0,
                         "Failed checking certificate %s: %s" % (cert_file,
                                                                 err_msg))
        # Check output key
        key_file = self.fqdn + "-key.pem"
        self.assert_(result.files_created.has_key(key_file))
        key_result = self.check_private_key(env, key_file)
        err_msg = self.run_error_msg(key_result)
        self.assertEqual(result.returncode, 0,
                         "Check of private key %s failed: %s" % (key_file,
                                                                 err_msg))

        # Revoke cert
        message = "Testing host certificate revocation"
        _, revoke_result, revoke_err_msg = self.run_gridadmin_script(self.command_revoke,
                                                                     "--pkey", self.get_key_path(),
                                                                     "--cert", self.get_cert_path(),
                                                                     request_id, message)
        match = re.search(r"^Successfully revoked host certificate with request ID: (\d+)\s*$",
                          revoke_result.stdout, re.MULTILINE)
        self.assert_(match, "Failure: Could not revoke certificate " + revoke_err_msg)

        return cert_result.stdout

    def test_help(self):
        """Test if we get the help message on osg-cert-revoke"""
        _, result, err_msg = self.run_gridadmin_script(self.command, "-h")
        self.assert_(re.search(r'[Uu]sage:', result.stdout), err_msg)

    def test_cert_request(self):
        """Test making a request for a single host"""
        self.request_and_revoke_cert(*self.request_args)

    def test_alt_name_request(self):
        """Test making a request for a single host with an alternative hostname"""
        san = 'test-san.' + self.domain
        second_san = 'test-san2.' + self.domain
        cert_contents = self.request_and_revoke_cert('--altname', san, '--altname', second_san, *self.request_args)
        found_names = set(match.group(1) for match in re.finditer(r'DNS:([\w\-\.]+)', cert_contents))
        expected_names = set([self.fqdn, san, second_san])
        self.assertEqual(found_names,
                         expected_names,
                         "Did not find expected SAN contents (%s):\n%s" %
                         (list(expected_names), cert_contents)) # printed lists are prettier than printed sets

if __name__ == '__main__':
    import unittest
    unittest.main()
