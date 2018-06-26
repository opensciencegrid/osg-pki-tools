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

PKG_REQS='yum-plugin-priorities rpm-build git gzip'
if [ $OS_VERSION -eq '6' ]; then
    PKG_REQS="$PKG_REQS python-unittest2"
fi

yum -y install $PKG_REQS

# Prepare the RPM environment
mkdir -p /tmp/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cat >> /etc/rpm/macros.dist << EOF
%dist .osg.el${OS_VERSION}
%osg 1
EOF

cp osg-pki-tools/rpm/osg-pki-tools.spec /tmp/rpmbuild/SPECS
package_version=`grep Version osg-pki-tools/rpm/osg-pki-tools.spec | awk '{print $2}'`
pushd osg-pki-tools
git archive --format=tar --prefix=osg-pki-tools-${package_version}/ HEAD | \
    gzip > /tmp/rpmbuild/SOURCES/osg-pki-tools-${package_version}.tar.gz
popd

# Build the RPM
rpmbuild --define '_topdir /tmp/rpmbuild' -ba /tmp/rpmbuild/SPECS/osg-pki-tools.spec

# After building the RPM, try to install it
# Fix the lock file error on EL7.  /var/lock is a symlink to /var/run/lock
mkdir -p /var/run/lock

RPM_LOCATION=
yum localinstall -y /tmp/rpmbuild/RPMS/noarch/osg-pki-tools-${package_version}*

# Run unit tests
pushd osg-pki-tools/
if [ $OS_VERSION -eq '6' ]; then
    PYTHONPATH=. python tests/test_cert_request.py
else
    python -m unittest discover -v tests
fi
popd

