"""Basic tests for test framework, credentials and python"""

import os
import os.path
import subprocess

import PKIClientTestCase

class BasicTests(PKIClientTestCase.PKIClientTestCase):
    def test_basic(self):
        """Test test framework"""
        env = self.get_test_env()
        result = env.run("echo", "Hello world")
        self.assertTrue("Hello world" in result.stdout)

    def test_user_cert(self):
        """Test that we can access the user's certificate for authentication"""
        user_cert_path = self.get_user_cert_path()
        self.assertTrue(os.path.exists(user_cert_path),
                        "User cert does not exist: " + user_cert_path)
        self.assertNotEqual(self._get_cert_modulus(), None)

    def test_user_key(self):
        """Test that we can access the user's key for authentication"""
        user_cert_path = self.get_user_cert_path()
        self.assertTrue(os.path.exists(user_cert_path),
                        "User cert does not exist: " + user_cert_path)
        self.assertNotEqual(self._get_key_modulus(), None)

    def test_cert_and_key_match(self):
        """Test that user cert and key modulus match"""
        self.assertEqual(self._get_cert_modulus(),
                         self._get_key_modulus())

    def test_pyOpenSSL(self):
        """Test that pyOpenSSL seems to work"""
        import OpenSSL

    def test_json(self):
        """Test we can import json or simplejson"""
        try:
            import json
        except ImportError:
            import simplejson as json

    #
    # Utility methods
    #

    def _get_cert_modulus(self):
        """Return modulus of certificate as string"""
        user_cert_path = self.get_user_cert_path()
        pipe = subprocess.Popen(
            [self.openssl, "x509", "-noout", "-modulus",
             "-in", user_cert_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pipe.wait()
        self.assertEqual(pipe.returncode, 0,
                         "Obtaining certificate modulus failed: " +
                         pipe.stderr.read())
        return pipe.stdout.read()

    def _get_key_modulus(self):
        """Return modulus of private key as string"""
        user_key_path = self.get_user_key_path()
        pass_phrase = self.get_user_key_pass_phrase()
        args = [self.openssl, "rsa", "-noout", "-modulus", "-in", user_key_path]
        if pass_phrase:
            args.extend(["-passin", "stdin"])
        pipe = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        # If we have no pass_phrase, this does no harm
        (key_modulus, error_text) = pipe.communicate(input=pass_phrase)
        self.assertEqual(pipe.returncode, 0,
                         "Obtaining key modulus failed: " + error_text)
        return key_modulus
