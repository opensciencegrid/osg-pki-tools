from distutils.core import setup
from osgpkitools import utils

setup(
    name="osg-pki-tools",
    url="https://github.com/opensciencegrid/osg-pki-tools",
    version=utils.VERSION_NUMBER,
    author="Brian Lin",
    author_email="blin@cs.wisc.edu",
    scripts=["osgpkitools/osg-cert-request", "osgpkitools/osg-incommon-cert-request"],
    description="Open Science Grid x509 certificate tools.",
    long_description="Open Science Grid x509 certificate tools.",
    packages=['osgpkitools'],
    license='Apache 2.0',
)


