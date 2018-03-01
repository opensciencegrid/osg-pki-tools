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

* osg-gridadmin-cert-request: This script is used to request approve, issue and retrieve certificate requests in bulks of 50 certificates at a time.

* osg-user-cert-renew : This script is used to renew user certificate.

* osg-user-cert-revoke : This script is required to revoke user certificate.

* osg-cert-revoke : This script is used to revoke host certificate(s).

Usage: osg-cert-request [options]
=================================

Options:
  -h, --help            show this help message and exit
  -c CSR, --csr=CSR     Specify CSR name (default = gennew.csr)
  -o OUTPUT KEYFILE, --outkeyfile=OUTPUT KEYFILE
                        Specify the output filename for the retrieved user certificate.
                        Default is ./hostkey.pem
  -v VO name, --vo=VO name
                        Specify the VO for the host request
  -y CC LIST, --cc=CC LIST
                        Specify the CC list(the email id's to be CCed).
                        Separate values by ','
  -m COMMENT, --comment=COMMENT
                        The comment to be added to the request
  -H CN, --hostname=CN  Specify a hostname for CSR (FQDN)
  -a HOSTNAME, --altname=HOSTNAME
                        Specify an alternative hostname for the CSR (FQDN). May be used more than once
  -e EMAIL, --email=EMAIL
                        Email address to receive certificate
  -n NAME, --name=NAME  Name of user receiving certificate
  -p PHONE, --phone=PHONE
                        Phone number of user receiving certificate
  -t TIMEOUT, --timeout=TIMEOUT
                        Specify the timeout in minutes
  -T, --test            Run in test mode
  -q, --quiet           don't print status messages to stdout
  -d WRITE_DIRECTORY, --directory=WRITE_DIRECTORY
                        Write the output files to this directory
  -V, --version         Print version information and exit



Usage: osg-cert-retrieve [options] <Request ID>
Usage: osg-cert-retrieve -h/--help [for detailed explanations of options]
========================================================================

Options:
  -h, --help            show this help message and exit
  -o ID, --certfile=ID  Specify the output filename for the retrieved user
                        certificate . Default is ./hostcert.pem
  -T, --test            Run in test mode
  -t TIMEOUT, --timeout=TIMEOUT
                        Specify the timeout in minutes
  -q, --quiet           don't print status messages to stdout
  -d WRITE_DIRECTORY, --directory=WRITE_DIRECTORY
                        Write the output files to this directory
  -V, --version         Print version information and exit
  -i, --id              Specify ID# of certificate to be retrieved
                        [deprecated]

Usage: osg-cert-revoke [options] <Request ID> <message>
Usage: osg-cert-revoke -h/--help [for detailed explanations of options]
======================================================================

Options:
  -h, --help            show this help message and exit
  -n, --certid          Treat the ID argument as the serial ID# for the
                        certificate to be revoked
  -u, --user            Certificate to be revoked is a user certificate.
                        Redundant when using `osg-user-cert-revoke`.
  -k PKEY, --pkey=PKEY  Specify Requestor's private key (PEM Format). If not
                        specified, this takes the value of X509_USER_KEY or
                        $HOME/.globus/userkey.pem
  -c CERT, --cert=CERT  Specify Requestor's certificate (PEM Format). If not
                        specified, this takes the value of X509_USER_CERT or
                        $HOME/.globus/usercert.pem
  -T, --test            Run in test mode
  -t TIMEOUT, --timeout=TIMEOUT
              Specify the timeout in minutes
  -q, --quiet           don't print status messages to stdout
  -V, --version         Print version information and exit
  -m REASON, --message=REASON
                        Specify the reason for certificate revocation
                        [deprecated]
  -i, --id              Specify ID# of certificate to be retrieved
                        [deprecated]


Usage: osg-gridadmin-cert-request [options] arg
Usage: osg-gridadmin-cert-request -h/--help [for detailed explanations of options]
=================================================================================


Options:
  -h, --help            show this help message and exit
  -k PKEY, --pkey=PKEY  Specify Requestor's private key (PEM Format). If not
                        specifiedwill take the value of X509_USER_KEY or
                        $HOME/.globus/userkey.pem
  -c CERT, --cert=CERT  Specify Requestor's certificate (PEM Format). If not
                        specified, will take the value of X509_USER_CERT or
                        $HOME/.globus/usercert.pem
  -a HOSTNAME, --altname=HOSTNAME
                        Specify an alternative hostname for CSR (FQDN). May be
                        used more than once and if specified, -f/--hostfile
                        will be ignored
  -v VO name, --vo=VO name
                        Specify the VO for the host request
  -y CC List, --cc=CC List
                        Specify the CC list(the email id's to be
                        CCed).Separate values by ','
  -T, --test            Run in test mode
  -t TIMEOUT, --timeout=TIMEOUT
                        Specify the timeout in minutes
  -q, --quiet           don't print status messages to stdout
  -d WRITE_DIRECTORY, --directory=WRITE_DIRECTORY
                        Write the output files to this directory
  -V, --version         Print version information and exit

  Hostname Options:
    Use either of these options. Specify hostname as a single hostname
    using -H/--hostname or specify from a file using -f/--hostfile.

    -H HOSTNAME, --hostname=HOSTNAME
                        Specify the hostname or service/hostname for which you
			want to request the certificate for. If specified,
                        -f/--hostfile will be ignored
    -f HOSTFILE, --hostfile=HOSTFILE
                        Filename with one host (hostname or service/hostname
                        and its optional,alternative hostnames, separated by
                        spaces) per line


Usage: osg-user-cert-renew [options]
===================================

Options:
  -h, --help            show this help message and exit
  -k PKEY, --pkey=PKEY  Specify Requestor's private key (PEM Format). If not
                        specified  will take the value of X509_USER_KEY or
                        $HOME/.globus/userkey.pem
  -c CERT, --cert=CERT  Specify Requestor's certificate (PEM Format).  If not
                        specified will take the value of X509_USER_CERT or
                        $HOME/.globus/usercert.pem
  -T, --test            Run in test mode
  -t TIMEOUT, --timeout=TIMEOUT
                        Specify the timeout in minutes
  -d WRITE_DIRECTORY, --directory=WRITE_DIRECTORY
                        Write the output files to this directory
  -q, --quiet           don't print status messages to stdout
  -V, --version         Print version information and exit

Usage: osg-user-cert-revoke [options] <Request ID> <message>
Usage: osg-user-cert-revoke -h/--help [for detailed explanations of options]
===========================================================================

Options:
  -h, --help            show this help message and exit
  -n, --certid          Treat the ID argument as the serial ID# for the
                        certificate to be revoked
  -u, --user            Certificate to be revoked is a user certificate.
                        Redundant when using `osg-user-cert-revoke`.
  -k PKEY, --pkey=PKEY  Specify Requestor's private key (PEM Format). If not
                        specified, this takes the value of X509_USER_KEY or
                        $HOME/.globus/userkey.pem
  -c CERT, --cert=CERT  Specify Requestor's certificate (PEM Format). If not
                        specified, this takes the value of X509_USER_CERT or
                        $HOME/.globus/usercert.pem
  -T, --test            Run in test mode
  -t TIMEOUT, --timeout=TIMEOUT
                        Specify the timeout in minutes
  -q, --quiet           don't print status messages to stdout
  -V, --version         Print version information and exit
  -m REASON, --message=REASON
                        Specify the reason for certificate revocation
                        [deprecated]
  -i, --id              Specify ID# of certificate to be retrieved
                        [deprecated]


