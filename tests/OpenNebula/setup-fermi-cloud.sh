#!/bin/sh
#
# Set up a FNAL cloud machine to use OSG software.
#
# Written by Alain Roy
 
check_root()
{
if [ $UID -ne 0 ]; then
echo "Must be root to run setup-fermi-cloud"
exit 1
fi
}
 
add_to_sudoers()
{
grep --quiet ${USER} /etc/sudoers
if [ $? -eq 0 ]; then
echo "${USER} is already in the sudoers file."
else
echo "${USER} is not in the sudoers file, adding:"
chmod 664 /etc/sudoers
cp /etc/sudoers /etc/sudoers.original
echo "${USER} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
chmod 440 /etc/sudoers
diff --unified=0 /etc/sudoers.original /etc/sudoers
fi
}
 
install_repos()
{
release=`lsb_release --release | awk '{print $2}' | awk -F . '{print $1}'`
 
if [ $release = "5" ]; then
install_repos_5
else
install_repos_6
fi
}
 
install_repos_5()
{
if [ ! -e epel-release-5-4.noarch.rpm ]; then
wget http://download.fedoraproject.org/pub/epel/5/i386/epel-release-5-4.noarch.rpm
fi
 
rpm -i epel-release-5-4.noarch.rpm
rpm -Uvh http://repo.grid.iu.edu/osg-el5-release-latest.rpm
}
 
install_repos_6()
{
if [ ! -e epel-release-6-5.noarch.rpm ]; then
wget http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-5.noarch.rpm
fi
 
rpm -i epel-release-6-5.noarch.rpm
rpm -Uvh http://repo.grid.iu.edu/osg-el6-release-latest.rpm
}
 
install_desired_rpms()
{
yum install -y yum-priorities
yum install -y krb5-fermi-getcert emacs subversion git strace htop pstack iotop iftop pylint
#yum install -y --enablerepo=osg-testing osg-build koji
}
 
add_to_mock_group()
{
grep --quiet "mock.*alainroy" /etc/group
if [ $? -eq 0 ]; then
echo "Alain is already in the mock group."
else
echo "Alain is not in the mock group, adding him:"
cp /etc/group /etc/group.original
sed -i -e 's/^\(mock.*\)/\1alainroy/' /etc/group
diff --unified=0 /etc/group.original /etc/group
fi
}
 
setup_ca_certs()
{
yum install -y osg-ca-certs
cat /etc/grid-security/certificates/d1b603c3.0 /etc/grid-security/certificates/1c3f2ca8.0 >> /etc/pki/tls/certs/ca-bundle.crt
}
 
setup_grid_mapfile()
{
echo '"/DC=org/DC=doegrids/OU=People/CN=Alain Roy 424511" alainroy' >> /etc/grid-security/grid-mapfile
chmod 644 /etc/grid-security/grid-mapfile
}
 
# Usally there is a host cert, but apparently not on SL6? We set it up if it's not there.
setup_host_cert()
{
host=`hostname -f`
 
if [ ! -e /etc/grid-security ]; then
mkdir /etc/grid-security
chmod 755 /etc/grid-security
fi
 
if [ ! -e /etc/grid-security/hostcert.pem ]; then
ln -s /etc/cloud-security/$host-hostcert.pem /etc/grid-security/hostcert.pem
fi
if [ ! -e /etc/grid-security/hostkey.pem ]; then
ln -s /etc/cloud-security/$host-hostkey.pem /etc/grid-security/hostkey.pem
fi
}
 
copy_rsv_certs()
{
getent group rsv >/dev/null || /usr/sbin/groupadd -r rsv
getent passwd rsv >/dev/null || /usr/sbin/useradd -r -g rsv -d /var/rsv -s /bin/sh -c "RSV monitoring" rsv
mkdir /etc/grid-security/rsv
cp /etc/grid-security/hostcert.pem /etc/grid-security/rsv/rsvcert.pem
cp /etc/grid-security/hostkey.pem /etc/grid-security/rsv/rsvkey.pem
chown -R rsv: /etc/grid-security/rsv
chmod 0444 /etc/grid-security/rsv/rsvcert.pem
chmod 0400 /etc/grid-security/rsv/rsvkey.pem
}
 
check_root
add_to_sudoers
install_repos
install_desired_rpms
#add_to_mock_group
#setup_ca_certs
#setup_grid_mapfile
#setup_host_cert
#copy_rsv_certs
exit 0
