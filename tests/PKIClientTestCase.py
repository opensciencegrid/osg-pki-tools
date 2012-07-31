"""PKIClientTestCase: OSG PKI Command line client test case base class"""

import os
import scripttest  # pip install scripttest
import unittest

class PKIClientTestCase(unittest.TestCase):
    """OSG PKI CLI TestCase bass class"""

    # TODO: Set this smartly.
    #       I tried to set from do-test.py, but doesn't seem to stick.
    cwd = ".."  # Should be path to scripts

    # Path to user certificate and private key to use for authentication
    user_cert_path = None
    user_key_path = None

    # Private key pass phrase
    pass_phrase = None

    # Openssl binary
    openssl = "openssl"

    @classmethod
    def get_TestFileEnvironment(cls):
        """Return a scripttest.TestFileEnvironment instance"""
        kwargs = {}
        kwargs["cwd"] = cls.cwd
        return scripttest.TestFileEnvironment("./test-output", **kwargs)

    @classmethod
    def run_script(cls, script, *args):
        """Run script with given arguments.

        Returns scriptTest.ProcResult instance from TestFileEnvironment.run()"""
        env = cls.get_TestFileEnvironment()
        result = env.run("python",  # In case script is not executable
                         script, *args,
                         # Don't raise exception on error
                         expect_error=True, expect_stderr=True, quiet=True)
        return result

    @classmethod
    def run_error_msg(cls, result):
        """Return an error message from a result"""
        return "Return code: %d\n" % result.returncode \
            + result.stdout + result.stderr

    @classmethod
    def set_user_cert_path(cls, path):
        """Set path to use for user certificate"""
        cls.user_cert_path = path

    @classmethod
    def get_user_cert_path(cls):
        """Return path to user certificate to use for authentication

        Search order is:
           Path specified by user on commandline
           X509_USER_CERT environment variable
           ~/.globus/usercert.pem"""
        if cls.user_cert_path:
            return cls.user_cert_path
        if os.environ.has_key("X509_USER_CERT"):
            return os.environ["X509_USER_CERT"]
        return os.path.expanduser("~/.globus/usercert.pem")

    @classmethod
    def set_user_key_path(cls, path):
        """Set path to use for user private key"""
        cls.user_key_path = path

    @classmethod
    def get_user_key_path(cls):
        """Return path to user private key to use for authentication

        Search order is:
           Path specified by user on commandline
           X509_USER_KEY environment variable
           ~/.globus/userkey.pem"""
        if cls.user_key_path:
            return cls.user_key_path
        if os.environ.has_key("X509_USER_KEY"):
            return os.environ["X509_USER_KEY"]
        return os.path.expanduser("~/.globus/userkey.pem")

    @classmethod
    def set_user_key_pass_phrase(cls, phrase):
        """Set user's private key pass phrase"""
        cls.pass_phrase = phrase

    @classmethod
    def get_user_key_pass_phrase(cls):
        """Get user's private key pass phrase"""
        return cls.pass_phrase
