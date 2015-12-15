"""PKIClientTestCase: OSG PKI Command line client test case base class"""

import os
import re
import shutil
import stat
import sys
import tempfile

from copy import deepcopy
from subprocess import Popen, PIPE
from M2Crypto import RSA, X509

# Flag to indicate we are testing an RPM install
TESTING_RPM_INSTALL = False

# Path to certificate and private key to use for authentication as a Grid Admin
# See README for details
GA_CERT_PATH = os.path.abspath("./test-cert.pem")
GA_KEY_PATH = os.path.abspath("./test-key.pem")

# Information to provide with requests
EMAIL = "osg-pki-cli-test@example.com"
NAME = "OSG PKI CLI Test Suite"
PHONE = "555-555-5555"

# Domain to use with host certificate requests
# The test credentials are registered in OIM-ITB for this domain,
# it is not arbitrary.
DOMAIN = "pki-test.opensciencegrid.org"

# Where the scripts are relative to the tests/ directory
SCRIPTS_PATH = os.path.abspath("../osgpkitools")

# Scripts import from osgpkitools, and it is up a directory
PYPATH = os.path.abspath("..")

# Our test directory
TEST_PATH = "./test-output"

# TODO: chdir strategy is a little silly
def test_env_setup():
    """Create a dir for tests to play in"""
    ini_file = os.path.join(SCRIPTS_PATH, 'pki-clients.ini')
    temp_dir = tempfile.mkdtemp(dir=os.getcwd())
    shutil.copy2(ini_file, temp_dir)
    os.chdir(temp_dir)

def test_env_teardown():
    """Blow up the test dir"""
    temp_dir = os.getcwd()
    os.chdir('..')
    shutil.rmtree(temp_dir)

def run_script(script, *args):
    '''Run osg-pki-tools script '''
    script_path = os.path.join(SCRIPTS_PATH, script)
    cmd = (sys.executable, script_path) + args
    test_env = deepcopy(os.environ)
    try:
        test_env['PYTHONPATH'] += ':%s' % PYPATH
    except KeyError:
        test_env['PYTHONPATH'] = PYPATH

    script_proc = Popen(cmd, stdout=PIPE, stderr=PIPE, env=test_env)
    stdout, stderr = script_proc.communicate()
    rc = script_proc.returncode
    diagnostic = "Command: %s\n" % ' '.join(cmd[1:]) \
                 + "Return code: %d\n" % rc \
                 + "STDOUT:\n" + stdout \
                 + "STDERR:\n" + stderr
    return rc, stdout, stderr, diagnostic

class OIM(object):
    """OIM and cert/key pair interface"""
    def __init__(self):
        """Create a cert instance"""
        self.reqid = ''
        self.certs = list()
        self.keys = list()

    def request(self, *opts):
        """Run osg-cert-request"""
        rc, stdout, stderr, msg = run_script('osg-cert-request',
                                             '--test',
                                             '--hostname', 'test.' + DOMAIN,
                                             '--email', EMAIL,
                                             '--name', NAME,
                                             '--phone', PHONE,
                                             '--comment', 'This is a comment',
                                             '--cc', 'test@example.com,test2@example.com',
                                             *opts)
        attr_regex = r'Writing key to ([^\n]+).*Request Id#: (\d+)'
        try:
            key_path, self.reqid = re.search(attr_regex, stdout, re.MULTILINE|re.DOTALL).groups()
        except AttributeError:
            msg = 'Could not parse stdout for key or request ID\n' + msg
        else:
            try:
                key = OIM.verify_key(key_path)
                self.keys.append(key)
            except KeyFileError, key_err:
                raise KeyFileError(key_err.message + msg)
        return rc, stdout, stderr, msg

    def gridadmin_request(self, *opts):
        """Run osg-gridadmin-request"""
        rc, stdout, stderr, msg = run_script('osg-gridadmin-cert-request',
                                             '--test',
                                             '--cert', GA_CERT_PATH,
                                             '--pkey', GA_KEY_PATH,
                                             *opts)
        # Populate instance attr
        try:
            self.reqid = re.search(r'Id is: (\d+)', stdout).group(1)
        except AttributeError:
            msg = 'Could not parse stdout for request ID\n' + msg
        certs = re.findall(r'Certificate written to (.*)', stdout)
        keys = re.findall(r'Writing key to (.*)', stdout)
        if len(certs) != len(keys):
            raise AssertionError('Mismatched number of issued certs and keys\n' + msg)

        # Verify permissions of created files, if any
        for cert_path, key_path in zip(certs, keys):
            try:
                cert = OIM.verify_cert(cert_path)
                key = OIM.verify_key(key_path)
            except CertFileError, cert_err:
                raise CertFileError(cert_err.message + msg)
            except KeyFileError, key_err:
                raise KeyFileError(key_err.message + msg)
            else:
                self.certs.append(cert)
                self.keys.append(key)
        return rc, stdout, stderr, msg

    def retrieve(self, *opts):
        """Run osg-cert-retrieve"""
        args = list(opts + (self.reqid))
        return run_script('osg-cert-retrieve', '--test', *args)

    def user_renew(self, *opts):
        """Run osg-user-cert-renew"""
        return run_script('osg-user-cert-renew', '--test', *opts)

    def revoke(self, *opts):
        """Run osg-cert-revoke"""
        args = opts + ('--test',
                       '--cert', GA_CERT_PATH,
                       '--pkey', GA_KEY_PATH,
                       self.reqid, 'osg-pki-tools unit test - revoke')
        return run_script('osg-cert-revoke', *args)

    def user_revoke(self, *opts):
        """Run osg-user-cert-revoke"""
        args = list(opts + ('--test', self.reqid, 'osg-pki-tools unit test - revoke'))
        return run_script('osg-user-cert-revoke', *args)

    @staticmethod
    def verify_key(path):
        """Ensure proper key permission bits and ability to unlock the key"""
        fail_prefix = 'VerificationFailure: '
        if not os.path.exists(path):
            raise KeyFileError(fail_prefix + "No associated key file")
        permissions = os.stat(path).st_mode & 0777 # Mask non-permission bits
        if permissions != 0600:
            raise KeyFileError(fail_prefix + "Bad permissions (%o) on key '%s'" % (permissions, path))
        try:
            key = RSA.load_key(path, OIM.simple_pass_callback)
        except RSA.RSAError, exc:
            if 'no start line' in exc.message:
                raise KeyFileError(fail_prefix + "Could not load key file '%s'" % path)
            elif 'bad pass' in exc.message:
                raise KeyFileError(fail_prefix + "Incorrect pass for key file %s" % path)
        return key

    @staticmethod
    def verify_cert(path):
        """Ensure proper cert permissions, returns"""
        fail_prefix = 'VerificationFailure: '
        if not os.path.exists(path):
            raise CertFileError(fail_prefix + "No associated cert file")
        mode = os.stat(path).st_mode
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise CertFileError(fail_prefix + "Cert file '%s' is excessively writable: %o" %(path, mode & 0777))
        try:
            cert = X509.load_cert(path)
        except X509.X509Error:
            raise CertFileError('Malformed cert: %s\n' % path)
        return cert

    @staticmethod
    def simple_pass_callback(verify):
        """Callback for unlocking keys with passwords in plaintext for testing."""
        return ''

class KeyFileError(AssertionError):
    pass

class CertFileError(AssertionError):
    pass
