#!/bin/sh
# Test request for 50 certificates.
#
# Note you will need to make sure quota has been reset for the test user
# as 50 is the daily max:
# https://oim-itb.grid.iu.edu/oim/contactedit?id=893
#

set -e  # Exit on any error

# Full path to this script
TESTS_PATH=$(cd `dirname $0` && pwd)

# Full path to where scripts are
SCRIPTS_PATH=$(cd `dirname $0`/../osgpkitools/ && pwd)

key_file=${TESTS_PATH}/test-key.pem
cert_file=${TESTS_PATH}/test-cert.pem
hosts_file=${TESTS_PATH}/hosts.50

# XXX: This assume PYTHONPATH is empty
export PYTHONPATH=$(cd `dirname $0`/../ && pwd)

# Run in scripts directory to find .ini file
cd ${SCRIPTS_PATH}

python osg-gridadmin-cert-request -T -f ${hosts_file} -k ${key_file} -c ${cert_file}

echo "Success."

exit 0
