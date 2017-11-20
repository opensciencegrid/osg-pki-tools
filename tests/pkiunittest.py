"""For testing the osg-pki-tools. The OIM class acts as an interface to OIM-ITB
via the osg-pkitools. Each OIM keeps track of its request ID and cert/key pairs
"""

import glob
import os
import re
import shutil
import stat
import sys
import tempfile

from copy import deepcopy
from subprocess import Popen, PIPE
from M2Crypto import RSA, X509

global TEST_PATH
global orig_env

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
DOMAIN = "pki-test.wisc.edu"
TEST_VO = "MIS"

# Where the scripts are relative to the tests/ directory
SCRIPTS_PATH = os.path.abspath("../osgpkitools")

# Scripts import from osgpkitools, and it is up a directory
PYPATH = os.path.abspath("..")

TEST_PATH = ''

def test_env_setup():
    """Create a test dir and environment"""
    # Required for cleanup and tests
    global TEST_PATH
    global orig_env

    # Set path and python path for tests
    orig_env = deepcopy(os.environ)
    try:
        os.environ['PYTHONPATH'] += ':%s' % PYPATH
    except KeyError:
        os.environ['PYTHONPATH'] = PYPATH
    os.environ['PATH'] += ':%s' % SCRIPTS_PATH

    # Create temp dir and place necessary config in the cwd
    ini_file = os.path.join(SCRIPTS_PATH, 'pki-clients.ini')
    cwd = os.getcwd()
    shutil.copy2(ini_file, cwd)
    TEST_PATH = tempfile.mkdtemp(dir=cwd)

def test_env_teardown():
    """Blow up the test dir"""
    os.environ = deepcopy(orig_env) # restore environment
    os.unlink('pki-clients.ini')
    shutil.rmtree(TEST_PATH)

def run_command(cmd, env=None):
    proc = Popen(cmd, stdout=PIPE, stderr=PIPE, env=env)
    stdout, stderr = proc.communicate()
    rc = proc.returncode
    diagnostic = "Command: %s\n" % ' '.join(cmd) \
                 + "Return code: %d\n" % rc \
                 + "STDOUT:\n" + stdout \
                 + "STDERR:\n" + stderr
    return rc, stdout, stderr, diagnostic

def run_python(script, *args):
    '''Run osg-pki-tools script '''
    script_path = os.path.join(SCRIPTS_PATH, script)
    py_cmd = (sys.executable, script_path) + args
    return run_command(py_cmd, env=os.environ)

class OIM(object):
    """OIM and cert/key pair interface"""
    def __init__(self):
        """Create a cert instance"""
        self.reqid = ''
        self.certs = list()
        self.keys = list()

    def request(self, *opts):
        """Run osg-cert-request"""
        rc, stdout, stderr, msg = run_python('osg-cert-request',
                                             '--test',
                                             '--comment', 'osg-pki-tools developer testing',
                                             '--cc', 'test@example.com,test2@example.com',
                                             '--directory', TEST_PATH,
                                             '--vo', TEST_VO,
                                             *opts)

        try:
            self.reqid = re.search(r'OIM Request ID: (\d+)', stdout).group(1)
        except AttributeError:
            msg = 'Could not parse stdout for key or request ID\n' + msg

        try:
            key_path = re.search(r'Writing key to ([^\n]+)', stdout).group(1)
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
        rc, stdout, stderr, msg = run_python('osg-gridadmin-cert-request',
                                             '--test',
                                             '--cert', GA_CERT_PATH,
                                             '--pkey', GA_KEY_PATH,
                                             '--directory', TEST_PATH,
                                             '--vo', TEST_VO,
                                             *opts)
        # Populate instance attr
        try:
            self.reqid = re.search(r'OIM Request ID: (\d+)', stdout).group(1)
        except AttributeError:
            msg = 'Could not parse stdout for request ID\n' + msg
        # find all certs and keys in the output dir as sorted lists
        certs = sorted([x for x in glob.glob(os.path.join(TEST_PATH, '*.pem')) if '-key.pem' not in x])
        keys = sorted(glob.glob(os.path.join(TEST_PATH, '*-key.pem')))
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
        if not self.reqid and '--help' not in opts:
            raise CertFileError('Could not revoke cert due to missing request ID\n')
        args = list(opts + (self.reqid,))
        return run_python('osg-cert-retrieve', '--test',
                          '--directory', TEST_PATH,
                          *args)

    def user_renew(self, *opts):
        """Run osg-user-cert-renew"""
        return run_python('osg-user-cert-renew', '--test', *opts)

    def revoke(self, *opts):
        """Run osg-cert-revoke"""
        if not self.reqid and '--help' not in opts:
            raise CertFileError('Could not revoke cert due to missing request ID\n')
        args = opts + ('--test',
                       '--cert', GA_CERT_PATH,
                       '--pkey', GA_KEY_PATH,
                       self.reqid, 'osg-pki-tools unit test - revoke')
        return run_python('osg-cert-revoke', *args)

    def user_revoke(self, *opts):
        """Run osg-user-cert-revoke, which is a bash wrapper around osg-cert-revoke"""
        if not self.reqid and '--help' not in opts:
            raise CertFileError('Could not revoke cert due to missing request ID\n')
        args = opts + ('--test', self.reqid, 'osg-pki-tools unit test - user revoke')
        cmd = (os.path.join(SCRIPTS_PATH, 'osg-user-cert-revoke'),) + args
        return run_command(cmd)

    @staticmethod
    def verify_key(path):
        """Ensure proper key permission bits and ability to unlock the key"""
        fail_prefix = 'VerificationFailure: '
        if not os.path.exists(path):
            raise KeyFileError(fail_prefix + "No associated key file\n")
        permissions = os.stat(path).st_mode & 0777 # Mask non-permission bits
        if permissions != 0600:
            raise KeyFileError(fail_prefix + "Bad permissions (%o) on key '%s'\n" % (permissions, path))
        try:
            key = RSA.load_key(path, OIM.simple_pass_callback)
        except RSA.RSAError, exc:
            if 'no start line' in exc.message:
                raise KeyFileError(fail_prefix + "Could not load key file '%s'\n" % path)
            elif 'bad pass' in exc.message:
                raise KeyFileError(fail_prefix + "Incorrect pass for key file %s\n" % path)
        return key

    @staticmethod
    def verify_cert(path):
        """Ensure proper cert permissions, returns"""
        fail_prefix = 'VerificationFailure: '
        if not os.path.exists(path):
            raise CertFileError(fail_prefix + "No associated cert file\n")
        mode = os.stat(path).st_mode
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise CertFileError(fail_prefix + "Cert file '%s' is excessively writable: %o\n" %(path, mode & 0777))
        try:
            cert = X509.load_cert(path)
        except X509.X509Error:
            raise CertFileError('Malformed cert: %s\n' % path)
        return cert

    @staticmethod
    def simple_pass_callback(verify):
        """Callback for unlocking keys with passwords in plaintext for testing."""
        return ''

    def assertNumCerts(self, num_expected_certs, msg):
        """Verify expected number of certs"""
        num_found_certs = len(self.certs)
        if num_found_certs != num_expected_certs:
            raise AssertionError('Expected %s cert(s), found %s\n%s' %
                                 (num_found_certs, num_expected_certs, msg))

    def assertSans(self, hosts_list, msg):
        """Verify that the we have the correct number of certs and expected SAN contents for each cert.
        If not, throw an AssertionError with details and msg

        hosts: list of lists containing hostname and its SANs
        msg: string"""
        self.assertNumCerts(len(hosts_list), msg)
        for cert, expected_names in zip(self.certs, hosts_list):
            # Verify list of SANs are as expected
            san_contents = cert.get_ext('subjectAltName').get_value()
            found_names = set(match.group(1) for match in re.finditer(r'DNS:([\w\-\.]+)', san_contents))
            if found_names != set(expected_names):
                raise AssertionError("Did not find expected SAN contents %s:\n%s\n%s" %
                                     (expected_names, cert.as_text(), msg))


class KeyFileError(AssertionError):
    pass

class CertFileError(AssertionError):
    pass
