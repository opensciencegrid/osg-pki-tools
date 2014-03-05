import os
from distutils.core import setup
from distutils.sysconfig import get_python_lib

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "OSGPKITools",
    version = "1.2.7",
    author = "Rohan Mathure",
    author_email = "rmathure@indiana.edu",
    maintainer = "Brian Lin",
    maintainer_email = "blin@cs.wisc.edu",
    description = ("A utility to request and manage certificates."),
    data_files = [('/usr/bin/',['osgpkitools/osg-cert-request', 'osgpkitools/osg-cert-retrieve', 'osgpkitools/osg-gridadmin-cert-request', 'osgpkitools/osg-cert-revoke', 'osgpkitools/osg-user-cert-revoke', 'osgpkitools/osg-user-cert-renew']),
                 ('/etc/osg/',['osgpkitools/pki-clients.ini']),
                 (os.path.join(get_python_lib(), 'osgpkitools/'),['osgpkitools/OSGPKIUtils.py','osgpkitools/__init__.py','osgpkitools/ExceptionDefinitions.py','osgpkitools/ConnectAPI.py'])],
    packages=['osgpkitools', 'tests'],
    long_description=read('README.txt'),
    classifiers=[
        "Development Status :: 1.2.7",
        "Topic :: Utilities",
        "Programming Language :: Python"
        "Operating System :: POSIX :: Linux"
    ],
)
