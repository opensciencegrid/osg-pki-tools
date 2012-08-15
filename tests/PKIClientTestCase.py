"""PKIClientTestCase: OSG PKI Command line client test case base class"""

import os
import os.path
import scripttest  # pip install scripttest
import unittest

class PKIClientTestCase(unittest.TestCase):
    """OSG PKI CLI TestCase bass class"""

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
    scripts_path = os.path.abspath("..")

    @classmethod
    def get_test_env(cls):
        """Return a scripttest.TestFileEnvironment instance"""
        # Make sure our source path is in PYTHONPATH so we can
        # find imports
        env = dict(os.environ)
        if env.has_key("PYTHONPATH"):
            env["PYTHONPATH"] += ":" + cls.scripts_path
        else:
            env["PYTHONPATH"] = cls.scripts_path
        env = scripttest.TestFileEnvironment("./test-output",
                                             environ=env,
                                             template_path=cls.scripts_path)
        # Copy in configuration file
        env.writefile("OSGPKIClients.ini", frompath="OSGPKIClients.ini")
        return env

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
            }
        result = env.run("python",  # In case script is not executable
                         os.path.join(cls.scripts_path, script),
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
            }
        result = env.run("env")
        result = env.run("python", "-c", code, *args, **kwargs)
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
