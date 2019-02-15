"""osg-cert-request tool module, separated from the script for unit testing
"""
from __future__ import print_function

import os
import re
import sys
import argparse

from collections import namedtuple
from M2Crypto import RSA, EVP, X509
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
    optional.add_argument('-d', '--directory', action='store', dest='write_directory', default='.',
                          help="The directory to write the generated CSR(s) and host key(s)")
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


def write_csr(output_dir, hostnames, location):
    """Write a Certificate Signing Request and private key

    Input:
    - output_dir: The destination directory to write the request and key
    - hostnames: A list of hostnames, the first of which is used as the Common Name.
    Additional hostnames are added to the list of Subject Alternative Names
    - location: A namedtuple containing country (e.g., US), state (e.g., Wisconsin),
    locality (e.g., Madison), and organization (e.g. Unversity of WIsconsin)
    """
    path = os.path.join(output_dir, hostnames[0] + '.req')
    keypath = os.path.join(output_dir, hostnames[0] + '-key.pem')

    keypair = RSA.gen_key(2048, 0x10001, lambda: None)
    utils.safe_write(keypath, keypair.as_pem(cipher=None))

    # The message digest shouldn't matter here since we don't use
    # PKey.sign_*() or PKey.verify_*() but there's no harm in keeping it and
    # it ensures a strong hashing algo (default is sha1) if we do decide to
    # sign things in the future

    x509request = X509.Request()
    x509name = X509.X509_Name()

    for key, val in [('C', location.country), ('ST', location.state), ('L', location.locality),
                     ('O', location.organization), ('CN', hostnames[0])]:
        x509name.add_entry_by_txt(field=key, type=0x1000 | 1, entry=val, len=-1, loc=-1, set=0)

    x509request.set_subject_name(x509name)

    extension_stack = X509.X509_Extension_Stack()
    extension = X509.new_extension('subjectAltName', ", ".join(['DNS:%s' % name for name in hostnames]))
    extension.set_critical(1)
    extension_stack.push(extension)
    x509request.add_extensions(extension_stack)

    pubkey = EVP.PKey(md='sha256')
    pubkey.assign_rsa(keypair)
    x509request.set_pubkey(pkey=pubkey)
    x509request.set_version(0)
    x509request.sign(pkey=pubkey, md='sha256')

    try:
        utils.safe_write(path, x509request.as_pem())
    except:
        os.remove(keypath)  # if we can't write the CSR, remove its associated privkey
        raise


def main():
    """The entrypoint for osg-cert-request
    """
    try:
        args = parse_cli(sys.argv[1:])
    except ValueError as exc:
        raise SystemExit(exc.message)

    location = namedtuple('Location', ['country', 'state', 'locality', 'organization'])
    loc = location(args.country, args.state, args.locality, args.organization)

    if args.hostname:
        fqdns_list = [[args.hostname] + args.altnames]
    elif args.hostfile:
        with open(args.hostfile, 'r') as hfile:
            hostfile = hfile.readlines()
        fqdns_list = [re.split(r' +', x) for x in hostfile]

    for fqdns in fqdns_list:
        print("Writing CSR for {0}...".format(fqdns[0]))
        write_csr(os.path.abspath(args.write_directory), fqdns, loc)
