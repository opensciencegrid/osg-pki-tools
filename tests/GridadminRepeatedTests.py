"""Test osg-gridadmin-cert-request script"""
### FIXING test for JIRA 332.

import os.path
import re

import PKIClientTestCase

class GridadminRepeatedTests(PKIClientTestCase.PKIClientTestCase):

    command = "osg-gridadmin-cert-request"

    def test_repeated_host_request(self):
	"""Test repeated requests for the same host to make sure
	we aren't overwriting files.

	For keys:
	Check if the key is already present as fqdn-key.pem
	
	If present then add '-old.pem' to the existing private key file.

	For certificates:
	Check if the certificate is present as fqdn.pem
	
	If present add '-old.pem' to existing cert file.

	See:
	https://jira.opensciencegrid.org/browse/OSGPKI-137
	https://jira.opensciencegrid.org/browse/OSGPKI-139
	"""
	num_requests = 2  # Number of certificates to request
	host_template = "test-%d." + self.domain
	hosts_filename = "hosts.txt"
	env = self.get_test_env()
	# Build contents of request file
	hosts_content = "\n".join(
	    [host_template % d for d in xrange(num_requests)]) + "\n"
	env.writefile(hosts_filename, content=hosts_content)
	result = self.run_script(env,
				 self.command,
				 "-f", hosts_filename,
				 "-k", self.get_key_path(),
				 "-c", self.get_cert_path())
	err_msg = self.run_error_msg(result)
	self.assertEqual(result.returncode, 0, err_msg)
	for cert_num in xrange(num_requests):
	    # Check output certificate
	    cert_file = host_template % cert_num + ".pem"
	    self.assertTrue(result.files_created.has_key(cert_file),
			    "Did not find certificate file %s: %s\n%s"
                            % (cert_file,
                               err_msg,
                               result.stdout))
	    # Check output key
	    key_file = host_template % cert_num + "-key.pem"
	    self.assertTrue(result.files_created.has_key(key_file),
			    "Did not find key file %s\n%s"
                            % (key_file, result.stdout))
	#
	# Now we repeat the request and look for files that include
	# request id to uniqify them
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
			    "Could not find request Id: %s\n%s"
                            % (err_msg, result.stdout))
	id = int(match.group(1))
	for cert_num in xrange(num_requests):
	    # Check output certificate
	    cert_file = host_template % cert_num + "-old.pem"
	    self.assertTrue(result.files_created.has_key(cert_file),
			    "Did not find certificate file %s: %s\n%s"
                            % (cert_file,
                               err_msg,
                               result.stdout))
	    # Check output key
	    key_file = host_template % cert_num + "-key-old.pem"
	    self.assertTrue(result.files_created.has_key(key_file),
			    "Did not find key file %s\n%s"
                            % (key_file, result.stdout))

if __name__ == '__main__':
    import unittest
    unittest.main()
