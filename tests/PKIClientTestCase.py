"""PKIClientTestCase: OSG PKI Command line client test case base class"""

import os
import os.path
import scripttest  # pip install scripttest
import stat
import sys
import unittest

class PKIClientTestCase(unittest.TestCase):
    """OSG PKI CLI TestCase bass class"""

    # Flag to indicate we are testing an RPM install
    testing_rpm_install=False

    # Path to certificate and private key to use for authentication
    # See README for details
    cert_path = os.path.abspath("./test-cert.pem")
    key_path = os.path.abspath("./test-key.pem")

    # Information to provide with requests
    email = "osg-pki-cli-test@example.com"
    name = "OSG PKI CLI Test Suite"
    phone = "555-555-5555"

    # Domain to use with host certificate requests
    # The test credentials are registered in OIM-ITB for this domain,
    # it is not arbitrary.
    domain = "pki-test.opensciencegrid.org"

    # Private key pass phrase
    pass_phrase = None

    # Openssl binary
    openssl = "openssl"

    # Where the scripts are relative to the tests/ directory
    scripts_path = os.path.abspath("../osgpkitools")

    # Scripts import from osgpkitools, and it is up a directory
    pypath = os.path.abspath("..")

    # Our test directory
    test_path = "./test-output"

    @classmethod
    def get_test_env(cls):
        """Return a scripttest.TestFileEnvironment instance"""
        # Make sure our source path is in PYTHONPATH so we can
        # find imports
        env = dict(os.environ)
        if cls.pypath is not None:
            if env.has_key("PYTHONPATH"):
                env["PYTHONPATH"] += ":" + cls.pypath
            else:
                env["PYTHONPATH"] = cls.pypath
        test_env = scripttest.TestFileEnvironment(
            cls.test_path,
            environ=env,
            template_path=cls.scripts_path)
        if not cls.testing_rpm_install:  # Should be installed by RPM
            # Copy in configuration file
            test_env.writefile("pki-clients.ini", frompath="pki-clients.ini")
        return test_env

    @classmethod
    def run_cmd(cls, env, *args):
        """Run given command.

        This is a wrapper around env.run() that won't throw an exception
        on error so we can handle errors in the test framework.

        Returns scriptTest.ProcResult instance from TestFileEnvironment.run()"""
        # Python 2.4 requires kwargs to be defined in variable and then
        # expanded in call to env.run instead of being supplied as keywords
        kwargs = {
            # Don't raise exception on error
            "expect_error" : True,
            "expect_stderr" : True,
            "quiet" : True,
	    #"test" : True,
            }
        result = env.run(*args, **kwargs)
        return result

    @classmethod
    def run_script(cls, env, script, *args):
        """Run script with given arguments.

        Returns scriptTest.ProcResult instance from TestFileEnvironment.run()"""
        # Python 2.4 requires kwargs to be defined in variable and then
        # expanded in call to env.run instead of being supplied as keywords
        kwargs = {
            # Don't raise exception on error
            "expect_error" : True,
            "expect_stderr" : True,
            "quiet" : True,
	    #"test" : True,
            }
        result = env.run(sys.executable,  # In case script is not executable
                         os.path.join(cls.scripts_path, script), "-T",
                         *args, **kwargs)
        return result

    def run_python(cls, code, *args):
        """Run given python code

        Returns scriptTest.ProcResult instance from TestFileEnvironment.run()"""
        env = cls.get_test_env()
        # Python 2.4 requires kwargs to be defined in variable and then
        # expanded in call to env.run instead of being supplied as keywords
        kwargs = {
            # Don't raise exception on error
            "expect_error" : True,
            "expect_stderr" : True,
            "quiet" : True,
	    #"test" : True,
            }
        result = env.run("env")
        result = env.run(sys.executable, "-c", code, "-T" ,*args, **kwargs)
        return result

    @classmethod
    def run_error_msg(cls, result):
        """Return an error message from a result"""
        return "Return code: %d\n" % result.returncode \
            + "STDOUT:\n" + result.stdout \
            + "STDERR:\n" + result.stderr

    @classmethod
    def set_cert_path(cls, path):
        """Set path to use for user certificate"""
        cls.cert_path = os.path.abspath(path)

    @classmethod
    def get_cert_path(cls):
        """Return path to user certificate to use for authentication

        Search order is:
           Path specified by user on commandline
           ./test-cert.pem"""
        return cls.cert_path

    @classmethod
    def set_key_path(cls, path):
        """Set path to use for user private key"""
        cls.key_path = os.path.abspath(path)

    @classmethod
    def get_key_path(cls):
        """Return path to user private key to use for authentication

        Search order is:
           Path specified by user on commandline
           ./test-key.pem"""
        return cls.key_path

    @classmethod
    def set_scripts_path(cls, path):
        """Set the path to where the scripts are"""
        cls.scripts_path = os.path.abspath(path)

    @classmethod
    def get_scripts_path(cls):
        """Get the path to where the scripts are"""
        return cls.scripts_path

    def check_private_key(self, env, path):
	"""Check the given private key in the given test environment using openssl

        Also asserts permissions of key file are 0600

	Returns scriptTest.ProcResult instance from TestFileEnvironment.run()"""
        mode = os.stat(os.path.join(self.test_path, path)).st_mode
        self.assertEqual(mode & 0777,  # Filter out non-permission bits
                         0600,
                         "Key file '%s' permissions are not 0600: %o" %(path, mode))
	result = self.run_cmd(env,
                              "openssl", "rsa",
                              "-in", path,
                              "-noout", "-check",
                              # This will cause us not to block on
                              # input if the key is encrypted. It will
                              # be ignored if the key isn't encrypted.
                              "-passin", "pass:null")
        return result

    def check_certificate(self, env, path):
        """Check the given certificate in the given test environment using openssl

        Also asserts certificate file is not group or world writable.

	Returns scriptTest.ProcResult instance from TestFileEnvironment.run()"""
        mode = os.stat(os.path.join(self.test_path, path)).st_mode
        self.assertEqual(mode & (stat.S_IWGRP | stat.S_IWOTH), 0,
                         "Cert file '%s' is excessively writable: %o" %(path, mode))
        result = self.run_cmd(env, "openssl", "x509", "-in", path, '-noout', '-text')
        return result

    @classmethod
    def setup_rpm_test(cls, path="/usr/bin/"):
        """Test an RPM install instead of from source."""
        # Override where to look for scripts
        cls.scripts_path = path
        # Don't override PYTHONPATH
        cls.pypath = None
        # And finally a flag for other things...
        cls.testing_rpm_install = True
