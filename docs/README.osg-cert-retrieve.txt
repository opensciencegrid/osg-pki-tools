Usage: osg-cert-retrieve [options] <Request ID>
Usage: osg-cert-retrieve -h/--help [for detailed explanations of options]

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
