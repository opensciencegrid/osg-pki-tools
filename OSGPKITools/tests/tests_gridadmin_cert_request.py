"""Test osg-gridadmin-cert-request script"""

import os.path
import re

import PKIClientTestCase

class GridadminCertRequestTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-gridadmin-cert-request"

    def test_help(self):
        """Test running with -h to get help"""
        env = self.get_test_env()
        result = self.run_script(env, self.command, "-h")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        self.assertTrue("Usage:" in result.stdout, err_msg)

    def test_single_host_request(self):
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
        match = re.search("Certificate written to (.*)$",
                          result.stdout,
                          re.MULTILINE)
        self.assertNotEqual(match, None,
                            "Could not find output certificate: " + err_msg)
        cert_file = match.group(1)
        # Check output certificate
        # Check output key
        # XXX This will change: https://jira.opensciencegrid.org/browse/OSGPKI-131
        key_file = fqdn + "-0-key.pem"
        self.assertTrue(result.files_created.has_key(key_file))
        result = self.run_cmd(env,
                              "openssl", "rsa",
                              "-in", key_file,
                              "-noout",
                              # This will cause us not to block on input if
                              # the key is encrypted. It will be ignored if the
                              # key isn't encrypted.
                              "-passin", "pass:null")
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)

    def test_multi_host_request(self):
        """Test making a request for multiple host certificates (-f)"""
        num_requests = 4  # Number of certificates to request
        host_template = "test-%d." + self.domain
        hosts_filename = "hosts.txt"
        env = self.get_test_env()
        # Build contents of request file
        hosts_content = "\n".join(
            [host_template % d for d in xrange(num_requests)])
        env.writefile(hosts_filename, content=hosts_content)
        result = self.run_script(env,
                                 self.command,
                                 "-f", hosts_filename,
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
        for cert_num in xrange(num_requests):
            # Check output certificate
            cert_file = "certificates/host-certs.%d-%d.pem" % (id, cert_num)
            self.assertTrue(
                "Certificate written to %s" % cert_file in result.stdout,
                "Could not find output of certificate %d:" % cert_num + err_msg)
            self.assertTrue(result.files_created.has_key(cert_file),
                            "Did not find certificate file %s" % cert_file)
            # XXX TODO: actually test certificate with openssl
            # Check output key
            # XXX This will change: https://jira.opensciencegrid.org/browse/OSGPKI-131
            key_file = host_template % cert_num + "-%d-key.pem" % (cert_num+1)
            self.assertTrue(result.files_created.has_key(key_file),
                            "Did not find key file %s" % key_file)
            openssl_result = \
                self.run_cmd(env,
                             "openssl", "rsa",
                             "-in", key_file,
                             "-noout",
                             # This will cause us not to block on input if
                             # the key is encrypted. It will be ignored if the
                             # key isn't encrypted.
                             "-passin", "pass:null")
            err_msg = self.run_error_msg(openssl_result)
            self.assertEqual(result.returncode, 0, err_msg)
