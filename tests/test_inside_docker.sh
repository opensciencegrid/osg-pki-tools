#!/bin/sh -xe

OS_VERSION=$1

ls -l /home

# Clean the yum cache
yum -y clean all
yum -y clean expire-cache

# First, install all the needed packages.
rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_VERSION}.noarch.rpm

# Broken mirror?
echo "exclude=mirror.beyondhosting.net" >> /etc/yum/pluginconf.d/fastestmirror.conf

PKG_REQS='yum-plugin-priorities m2crypto'
if [ $OS_VERSION -eq '6' ]; then
    PKG_REQS="$PKG_REQS python-unittest2 python-argparse"
fi

yum -y install $PKG_REQS

# Run unit tests
pushd osg-pki-tools/
if [ $OS_VERSION -eq '6' ]; then
    PYTHONPATH=. python tests/test_cert_request.py
else
    python -m unittest discover -v tests
fi
popd

