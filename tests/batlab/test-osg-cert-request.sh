#!/bin/sh
#
# Test osg-cert-request

set -e  # Exit on any error
echo "Testing osg-cert-request -h"
${PYTHON} ${SCRIPTS_PATH}/osg-cert-request -h >/dev/null
