"""Test osg-gridadmin-cert-request script"""

import os.path
import re

import PKIClientTestCase

class GridadminDuplicateHostTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-gridadmin-cert-request"

    def test_duplicate_host_request(self):
        """Test making sure we ignore duplicate hosts in request.

        Also tests ability to ignore extra whitespace and missing final
        carriage return.

        https://jira.opensciencegrid.org/browse/OSGPKI-138"""
        hosts_filename = "hosts.txt"
        env = self.get_test_env()
        # Build contents of request file
        # Leave off final carraiage return and add extra whitespace to
        # test that as well.
        hosts_content = "host-1." + self.domain + "   \n" + \
            "host-1." + self.domain + "\n" + \
            "  host-2." + self.domain + " \n" + \
            " host-1." + self.domain + "  "  # Should be ignored
        env.writefile(hosts_filename, content=hosts_content)
        result = self.run_script(env,
                                 self.command,
                                 "-f", hosts_filename,
                                 "-k", self.get_key_path(),
                                 "-c", self.get_cert_path())
        err_msg = self.run_error_msg(result)
        self.assertEqual(result.returncode, 0, err_msg)
        # Make sure duplicate was detected
        match = re.search("Duplicate Hostname entry for host-1." + self.domain,
                          result.stdout,
                          re.MULTILINE)
        self.assertNotEqual(match, None,
                            "Duplicate host entry not detected\n" + result.stdout)
        # Now make sure non-duplicate didn't trigger false positive
        match = re.search("Duplicate Hostname entry for host-2." + self.domain,
                          result.stdout,
                          re.MULTILINE)
        self.assertEqual(match, None,
                         "Non-duplicate host entry detected as duplicate\n" + result.stdout)
        # Check for output files
        cert_template = "host-%d." + self.domain + ".pem"
        key_template = "host-%d." + self.domain + "-key.pem"
        for host in [1,2]:
            cert_file = cert_template % host
            self.assertTrue(result.files_created.has_key(cert_file),
                            "Did not file certificate file %s\n" % cert_file  + result.stdout)
            key_file = key_template % host
            self.assertTrue(result.files_created.has_key(key_file),
                            "Did not file key file %s\n" % key_file + result.stdout)

if __name__ == '__main__':
    import unittest
    unittest.main()
