#!/bin/sh

# Eventual return status, will be set to non-zero on error
status=0

echo "Running BaTLab tests"
/bin/date
uname -a
svn info

export TESTS_PATH=$(cd `dirname $0`; pwd)
echo "TESTS_PATH=${TESTS_PATH}"
export SCRIPTS_PATH=$(cd `dirname $0`; cd ../../osgpkitools; pwd)
echo "SCRIPTS_PATH=${SCRIPTS_PATH}"
export PYTHON="python"
echo "PYTHON=${PYTHON}"

shopt -s nullglob  # Returns empty string if nothing matches glob
for test in ${TESTS_PATH}/test-*.sh ; do
    echo "Executing test: ${test}"
    ${test}
    if test $? -ne 0 ; then
        echo "Exit status: $?"
        status=1
    fi
    echo "Test complete: ${test}"
done

echo "BaTLab tests complete."
/bin/date
exit ${status}

