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

    def test_cert(self):
	"""Test that we can access the test certificate"""
	cert_path = self.get_cert_path()
	self.assertTrue(os.path.exists(cert_path),
			"Test cert does not exist: " + cert_path)
	self.assertNotEqual(self._get_cert_modulus(), None)

    def test_key(self):
	"""Test that we can access the test key"""
	key_path = self.get_key_path()
	self.assertTrue(os.path.exists(key_path),
			"Test key does not exist: " + key_path)
	self.assertNotEqual(self._get_key_modulus(), None)

    def test_cert_and_key_match(self):
	"""Test that cert and key modulus match"""
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
	cert_path = self.get_cert_path()
	pipe = subprocess.Popen(
	    [self.openssl, "x509", "-noout", "-modulus",
	     "-in", cert_path],
	    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	pipe.wait()
	self.assertEqual(pipe.returncode, 0,
			 "Obtaining certificate modulus failed: " +
			 cert_path + "\n" +
			 pipe.stderr.read())
	return pipe.stdout.read()

    def _get_key_modulus(self):
	"""Return modulus of private key as string"""
	key_path = self.get_key_path()
	pipe = subprocess.Popen(
	    [self.openssl, "rsa", "-noout", "-modulus", "-in", key_path],
	    stdout=subprocess.PIPE,
	    stderr=subprocess.PIPE)
        pipe.wait()
	self.assertEqual(pipe.returncode, 0,
			 "Obtaining key modulus failed: " +
			 key_path + "\n" +
			 pipe.stderr.read())
	return pipe.stdout.read()
