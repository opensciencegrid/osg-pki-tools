Usage: osg-cert-revoke [options] <Request ID> <message>
Usage: osg-cert-revoke -h/--help [for detailed explanations of options]

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
