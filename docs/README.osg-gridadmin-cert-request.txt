Usage: osg-gridadmin-cert-request [options] arg
Usage: osg-gridadmin-cert-request -h/--help [for detailed explanations of options]

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
