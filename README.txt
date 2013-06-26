===========
OSGPKI
===========

OSGPKI(Open Science Grid Public Key Infrastructure) provides command line interface to request, manage, retrieve certificates. You might find
it most useful for tasks involving request and retrieval of certificates in bulk.


Content
=========

The utilities included in the package:

* osg-cert-request: This script is used to request new certificates by unauthenticated users.

* osg-cert-retrieve: This script is used to retrieve the certificate requested by the request script if it is approved by the GridAdmin.

* osg-gridadmin-manage: This script is used to approve, reject or cancel certificate requests that are made.

* osg-gridadmin-cert-request: This script is used to request approve, issue and retrieve certificate requests in bulks of 50 certificates at a time.

* osg-user-cert-renew : This script is used to renew user certificate.

* osg-user-cert-revoke : This script is required to revoke user certificate.

* osg-cert-revoke : This script is used to revoke host certificate(s).