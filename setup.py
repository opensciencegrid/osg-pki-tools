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
    name="osg-pki-tools",
    version="2.1.4",
    author="Rohan Mathure",
    author_email="rmathure@indiana.edu",
    maintainer="Brian Lin",
    maintainer_email="blin@cs.wisc.edu",
    description=("Open Science Grid utility to generate certificate signing requests."),
    data_files=[('/usr/bin/osgpkitools/osg-cert-request'),
                (os.path.join(get_python_lib(), 'osgpkitools/'),
                 ['osgpkitools/request.py', 'osgpkitools/utils.py', 'osgpkitools/__init__.py'])],
    packages=['osgpkitools'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 1.2.20",
        "Topic :: Utilities",
        "Programming Language :: Python"
        "Operating System :: POSIX :: Linux"
    ],
)
