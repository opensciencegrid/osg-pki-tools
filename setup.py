import os
from distutils.core import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "OSGPKITools",
    version = "1.0.3",
    author = "Rohan Mathure",
    author_email = "rmathure@indiana.edu",
    description = ("A utility to request and manage certificates."),
    data_files = [('/usr/bin/',['osgpkitools/osg-cert-request', 'osgpkitools/osg-cert-retrieve', 'osgpkitools/osg-gridadmin-cert-request']),
                 ('/etc/osg/',['osgpkitools/pki-clients.ini']),
                 ('/usr/lib/python2.4/site-packages/osgpkitools/',['osgpkitools/OSGPKIUtils.py','osgpkitools/__init__.py','osgpkitools/ExceptionDefinitions.py'])],
    packages=['osgpkitools', 'tests'],
    long_description=read('README.txt'),
    classifiers=[
        "Development Status :: 1 - Alpha",
        "Topic :: Utilities",
        "Programming Language :: Python"
        "Operating System :: POSIX :: Linux"
    ],
)
