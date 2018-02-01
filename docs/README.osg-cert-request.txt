Usage: osg-cert-request [options]

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
