"""PKIClientTestCase: OSG PKI Command line client test case base class"""

import os
import os.path
import scripttest  # pip install scripttest
import unittest

class PKIClientTestCase(unittest.TestCase):
    """OSG PKI CLI TestCase bass class"""

    # Path to user certificate and private key to use for authentication
    user_cert_path = None
    user_key_path = None

    # Information to provide with requests
    email = "osg-pki-cli-test@example.com"
    name = "OSG PKI CLI Test Suite"
    phone = "555-555-5555"

    # Domain to use with host certificate requests
    domain = "bw.iu.edu"  # XXX: This is specific to Von

    # Private key pass phrase
    pass_phrase = None

    # Openssl binary
    openssl = "openssl"

    # Where the source files are relative to the tests/ directory
    source_path = os.path.join("..")

    @classmethod
    def get_test_env(cls):
        """Return a scripttest.TestFileEnvironment instance"""
        # Make sure our source path is in PYTHONPATH so we can
        # find imports
        env = dict(os.environ)
        python_path = os.path.join("..",  # testenv dir to this one
                                   cls.source_path)
        if env.has_key("PYTHONPATH"):
            env["PYTHONPATH"] += ":" + python_path
        else:
            env["PYTHONPATH"] = python_path
        env = scripttest.TestFileEnvironment("./test-output",
                                             environ=env,
                                             template_path=cls.source_path)
        # Copy in configuration file
        env.writefile("OSGPKIClients.ini", frompath="OSGPKIClients.ini")
        return env

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
                         os.path.join("..", "..", script),
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
