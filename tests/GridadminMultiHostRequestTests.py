"""Test osg-gridadmin-cert-request script"""

import re

from PKIClientTestCase import PKIClientTestCase

class GridadminMultiHostRequestTests(PKIClientTestCase):

    __num_requests = 4  # Number of certificates to request

    def __multiple_host_request(self, hosts):
        """Submit a GridAdmin request for multiple host certs and verify
        retrieval of cert/key pair

        hosts: list holding lists of SANs with the CN as the first SAN"""

        # Write the hosts input file
        env = self.get_test_env()
        hosts_filename = "hosts.txt"
        hosts_contents = str()
        for sans in hosts:
            hosts_contents += " ".join(sans) + "\n"
        env.writefile(hosts_filename, content=hosts_contents)

        # Submit the request and check the return code
        result = self.run_script(env,
                                 "osg-gridadmin-cert-request",
                                 "--hostfile", hosts_filename,
                                 "--pkey", self.get_key_path(),
                                 "--cert", self.get_cert_path())
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        match = re.search(r"^Id is: (\d+)\s*$",
                          result.stdout,
                          re.MULTILINE)
        self.assert_(match,"Could not find request Id: " + err_msg)

        # Verify output
        for sans in hosts:
            fqdn = sans[0]
            # Check output certificate
            cert_file = fqdn + ".pem"
            self.assert_("Certificate written to ./%s" % cert_file in result.stdout,
                "Could not find output of certificate (%s): %s" % (cert_file, err_msg))
            self.assert_(result.files_created.has_key(cert_file),
                            "Did not find certificate file %s: %s" % (cert_file, err_msg))
            # Check permissions
            cert_result = self.check_certificate(env, cert_file)
            err_msg = self.run_error_msg(cert_result)
            self.assertEqual(result.returncode, 0,
                             "Failed checking certificate %s: %s" % (cert_file, err_msg))
            # Check output key
            key_file = fqdn + "-key.pem"
            self.assert_(result.files_created.has_key(key_file),
                            "Did not find key file %s" % key_file)
            # Check permissions
            key_result = self.check_private_key(env, key_file)
            err_msg = self.run_error_msg(key_result)
            self.assertEqual(result.returncode, 0,
                             "Check of private key %s failed: %s" % (key_file, err_msg))
            # Verify expected hosts in the SANs extension
            cert_contents = cert_result.stdout
            self.assertEqual(set(match.group(1) for match in re.finditer(r'DNS:([\w\-\.]+)', cert_contents)),
                             set(sans),
                             "Did not find expected SAN contents (%s):\n%s" % (sans, cert_contents))

    def test_multi_host_request(self):
        """Test making a request for multiple host certificates"""
        hosts = list(["test-%d.%s" % (i, self.domain)] for i in xrange(self.__num_requests))
        self.__multiple_host_request(hosts)

    def test_sans_request(self):
        """Submit cert request for multiple hosts with SANs for each host"""
        hosts = list()
        for i in xrange(self.__num_requests):
            hosts.append([name.format(i, self.domain) for name in
                          ["test-{0}.{1}", "test-{0}-san.{1}", "test-{0}-san2.{1}"]])
        self.__multiple_host_request(hosts)

    def test_mixed_multi_host_request(self):
        """Submit cert request for multiple hosts with SANs for some hosts """
        mixed_hosts = list()
        for i in xrange(self.__num_requests):
            if i % 2 == 1:
                mixed_hosts.append(["test-%d.%s" % (i, self.domain)])
            else:
                mixed_hosts.append([name.format(i, self.domain) for name in
                                    ["test-{0}.{1}", "test-{0}-san.{1}", "test-{0}-san2.{1}"]])
        self.__multiple_host_request(mixed_hosts)

if __name__ == '__main__':
    import unittest
    unittest.main()
