"""Test osg-gridadmin-cert-request script"""

import os.path
import re

import PKIClientTestCase

class GridadminCertSingleHostRequestAndRevocationTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-gridadmin-cert-request"
    command_revoke = "osg-cert-revoke"
    # Define a class variable to store the requestID obtained from 
    # test001_single_host_request()
    id = "" 
    
    def test1_single_host_request(self):
        """Test making a request for a single host (-H)"""
        env = self.get_test_env()
        fqdn = "test." + self.domain
        result = self.run_script(env,
                                 self.command,
                                 "-H", fqdn,
                                 "-k", self.get_key_path(),
                                 "-c", self.get_cert_path())
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        match = re.search("^Id is: (\d+)\s*$",
                          result.stdout,
                          re.MULTILINE)
        self.assertNotEqual(match, None,
                            "Could not find request Id: " + err_msg)
        id = int(match.group(1))
        # Set the class variable id to the id obtained from single host request.
        GridadminCertSingleHostRequestAndRevocationTests.id = id

        match = re.search("Certificate written to (.*)$",
                          result.stdout,
                          re.MULTILINE)
        self.assertNotEqual(match, None,
                            "Could not find output certificate: " + err_msg)
        cert_file = match.group(1)
        # Check output certificate
        cert_result = self.check_certificate(env, cert_file)
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0,
                         "Failed checking certificate %s: %s" % (cert_file,
                                                                 err_msg))
        # Check output key
        key_file = fqdn + "-key.pem"
        self.assertTrue(result.files_created.has_key(key_file))
        key_result = self.check_private_key(env, key_file)
        err_msg = self.run_error_msg(key_result)
        self.assertEqual(result.returncode, 0,
                         "Check of private key %s failed: %s" % (key_file,
                                                                 err_msg))
        
        
    def test2_host_cert_revocation(self):
        """Test revoking a host certificate. obtained from the test001_single_host_request stored in the static variable id"""
        reqID = GridadminCertSingleHostRequestAndRevocationTests.id
        env = self.get_test_env()
        message = "Testing host certificate revocation"
        result = self.run_script(env,
                                 self.command_revoke,
                                 "-m", message,
                                 "-k", self.get_key_path(),
                                 "-c", self.get_cert_path(),
                                 "-i", reqID)
        err_msg = self.run_error_msg(result)
        
        self.assertEqual(result.returncode, 0, err_msg)
        match = re.search("^Sucessfully revoked certificate with request ID (\d+)\s*$",
                          result.stdout,
                          re.MULTILINE)
        self.assertNotEqual(match, None, "Failure, could not revoke certificate " + err_msg)
    
    def test_help(self):
        """Test if we get the help message on osg-cert-revoke"""
        env = self.get_test_env()
        result = self.run_script(env, self.command_revoke, "-h")
        err_msg = self.run_error_msg(result)
        self.assertTrue("Usage:" in result.stdout or "usage:" in result.stdout, err_msg)

if __name__ == '__main__':
    import unittest
    unittest.main()
