Usage: osg-user-cert-renew [options]

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
