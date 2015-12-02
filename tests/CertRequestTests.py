"""Test cert-request script"""

import re

from PKIClientTestCase import PKIClientTestCase

class CertRequestTests(PKIClientTestCase):

    command = "osg-cert-request"
    required_args = ["--hostname", "test." + PKIClientTestCase.domain,
                     "--email", PKIClientTestCase.email,
                     "--name", PKIClientTestCase.name,
                     "--phone", PKIClientTestCase.phone,
                     "--comment", "This is a comment",
                     "--cc", "test@example.com,test2@example.com"]

    def __run_cert_request(self, *args, **kwargs):
        rc = 0
        if kwargs.has_key('rc'):
            rc = kwargs['rc']

        env = self.get_test_env()
        result = self.run_script(env, self.command, *args)
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, rc, err_msg)
        return (env, result, err_msg)

    def __verify_output_files(self, env, result, err_msg):
        match = re.search("^Request Id#: (\d+)\s*$", result.stdout, re.MULTILINE)
        self.assert_(match, "Could not find request Id: " + err_msg)
        self.assert_(result.files_created.has_key("hostkey.pem"))
        key_file = "hostkey.pem"
        key_result = self.check_private_key(env, key_file)
        err_msg = self.run_error_msg(key_result)
        self.assertEqual(result.returncode, 0, "Check of private key %s failed: %s" % (key_file, err_msg))
    
    def test_help(self):
        """Test running with -h to get help"""
        _, result, err_msg = self.__run_cert_request("-h")
        # Python 2.4 optpase prints "usage" instead of "Usage"
        self.assert_(re.search(r'[Uu]sage:', result.stdout), err_msg)

    def test_no_args(self):
        """Test running without arguments and seeing usage"""
        _, result, err_msg = self.__run_cert_request(rc = 2)
        # Python 2.4 optpase prints "usage" instead of "Usage"
        self.assert_(re.search(r'[Uu]sage:', result.stderr), err_msg)

    def test_request(self):
        """Test making a request with required options and verify priv key creation"""
        env, result, err_msg = self.__run_cert_request(*self.required_args)
        self.__verify_output_files(env, result, err_msg)

    def test_alt_name_request(self):
        """Test cert request with alternative name and verify priv key creation"""
        alias = 'test-san.' + self.domain
        env, result, err_msg = self.__run_cert_request("--altname", alias, *self.required_args)
        self.__verify_output_files(env, result, err_msg)

if __name__ == '__main__':
    import unittest
    unittest.main()
