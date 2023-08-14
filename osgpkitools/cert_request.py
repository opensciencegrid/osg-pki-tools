"""osg-cert-request tool module, separated from the script for unit testing
"""

import os
import re
import sys
import argparse

from collections import namedtuple
from M2Crypto import RSA, EVP, X509
from osgpkitools import cert_utils
from osgpkitools import utils


def parse_cli(args):
    """This function parses all the arguments, validates them and then stores
    them in a dictionary that is used throughout in the script."""

    parser = argparse.ArgumentParser(add_help=False,  # disable built-in help to control help message ordering
                                     description='Generate certificate signing requests (CSRs) and private keys.')

    required = parser.add_argument_group('Required', 'Specify only one of -H/--hostname and -F/--hostfile')
    hosts = required.add_mutually_exclusive_group(required=True)
    hosts.add_argument('-H', '--hostname', action='store', dest='hostname',
                       help='The hostname (FQDN) to request')
    hosts.add_argument('-F', '--hostfile', action='store', dest='hostfile',
                       help='File containing list of hostnames (FQDN), one per line, to request. Space separated '
                       'subject alternative names (SANs) may be specified on the same line as each hostname.')
    required.add_argument('-C', '--country', action=CountryAction, required=True, dest='country',
                          help='The 2-letter country code to associate with the generated CSR(s)')
    required.add_argument('-S', '--state', action=StateAction, required=True, dest='state',
                          help='The unabbreviated state/province to associate with the generated CSR(s)')
    required.add_argument('-L', '--locality', action='store', required=True, dest='locality',
                          help='The locality (i.e., city, town) to associate with the generated CSR(s)')
    required.add_argument('-O', '--organization', action='store', required=True, dest='organization',
                          help='The organization to associate with the generated CSR(s)')

    optional = parser.add_argument_group("Optional")
    optional.add_argument('-h', '--help', action='help',
                          help='show this help message and exit')
    optional.add_argument('-a', '--altname', action='append', dest='altnames', default=[],
                          help='Specify the SAN for the requested certificate (only works with -H/--hostname). '
                          'May be specified more than once for additional SANs.')
    required.add_argument('-U', '--organizational-unit', action='append', dest='organizational_unit', default=[],
                          help='The organizational unit(s) to associate with the generated CSR(s)')
    optional.add_argument('-d', '--directory', action='store', dest='write_directory', default='.',
                          help="The directory to write the generated CSR(s) and host key(s)")
    optional.add_argument('-l', '--key-length', action='store', default=cert_utils.Csr.KEY_LENGTH,
                          type=int, help='The key size to generate')
    optional.add_argument('-V', '--version', action='version', version=utils.VERSION_NUMBER)

    parsed_args = parser.parse_args(args)

    # We can't add altnames to the mutually exclusive 'hosts' group since it's not a required opt
    if parsed_args.hostfile and parsed_args.altnames:
        parsed_args.altnames = []
        print("-A/--altname option ignored with -F/--hostfile", file=sys.stderr)

    return parsed_args


class CountryAction(argparse.Action):
    """Action for validating state/province options
    """
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("-C/--country only accepts a single argument")
        super(CountryAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if values.isalpha() and len(values) == 2:
            setattr(namespace, self.dest, values)
        else:
            parser.print_usage()
            raise ValueError("Values for -C/--country should be the two-letter country code.")


class StateAction(argparse.Action):
    """Action for validating state/province options
    """
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("-S/--state only accepts a single argument")
        super(StateAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) > 2:
            setattr(namespace, self.dest, values)
        else:
            parser.print_usage()
            raise ValueError("Values for -S/--state should be the unabbreviated form of the state or province.")


def main():
    """The entrypoint for osg-cert-request
    """
    try:
        args = parse_cli(sys.argv[1:])
    except ValueError as exc:
        sys.exit(exc)

    location = namedtuple('Location', ['country', 'state', 'locality', 'organization', 'organizational_unit'])
    loc = location(args.country, args.state, args.locality, args.organization, args.organizational_unit)

    if args.hostname:
        fqdns_list = [[args.hostname] + args.altnames]
    elif args.hostfile:
        with open(args.hostfile, 'r') as hfile:
            hostfiles = [x.strip() for x in hfile.readlines()]
            hostfiles = [x for x in hostfiles if x]
        fqdns_list = [re.split(r' +', x) for x in hostfiles]

    for fqdns in fqdns_list:
        print(f"Writing CSR for {fqdns[0]}...")
        csr_obj = cert_utils.Csr(fqdns[0], output_dir=os.path.abspath(args.write_directory), altnames=fqdns[1:], location=loc, key_length=args.key_length)
        csr_obj.write_pkey()
        csr_obj.write_csr()
