OSG PKI Tools
=============

The Open Science Grid (OSG) Private Key Infrastructure (PKI) Tools provide a convenient command-line interface for
common X.509 certificate commands used by OSG site administrators.
Formerly, this repository contained a collection of tools to request, approve, renew, and revoke certificates from the
[OSG Certificate Authority (CA)](https://opensciencegrid.org/technology/policy/service-migrations-spring-2018/#osg-ca).
This repository contains tools for generating Certificate Signing Requests and for getting host or service certificates from the InCommon CA.

osg-cert-request
----------------

The `osg-cert-request` tool generates [certificate signing requests (CSRs)](https://en.wikipedia.org/wiki/Certificate_signing_request)
that can be submitted to CAs (e.g. InCommon) for the purpose of obtaining host certificates.

**Features:**

- Bulk generation of CSRs (and associated keys)
- Easy addition of Subject Alternative Names (SANs) to each CSR

### Synopsis ###

```
usage: osg-cert-request (-H HOSTNAME | -F HOSTFILE) -C COUNTRY -S STATE -L LOCALITY -O ORGANIZATION
                        [-h] [-a ALTNAMES] [-d WRITE_DIRECTORY] [-V]
```

See osg-cert-request -h for a description of the options.


osg-incommon-cert-request
-------------------------

The `osg-incommon-cert-request` retrieves host or service certificates
from the InCommon CA.  It requires a user account with InCommon
authorized to use the remote API, and a user certificate and key issued
by InCommon that is authorized to create host certificates for that account.

**Features:**

- Bulk retrieval of certificates & keys
- Easy addition of Subject Alternative Names (SANs) to each certificate

### Synopsis ###

```
Usage: osg-incommon-cert-request [--debug] -u username -k pkey -c cert \
           (-H hostname | -F hostfile) [-a altnames] [-d write_directory]
       osg-incommon-cert-request [--debug] -u username -k pkey -c cert -t
       osg-incommon-cert-request [--orgcode org,dept] (-H hostname | \
       -F hostfile) -u username -k pkey -c cert
       osg-incommon-cert-request -h
       osg-incommon-cert-request --version
```

See osg-incommon-cert-request -h for a description of the options.
