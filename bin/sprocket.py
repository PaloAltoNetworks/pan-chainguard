#!/usr/bin/env python3

#
# Copyright (c) 2024 Palo Alto Networks, Inc.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import argparse
import asyncio
import csv
import json
import os
import pprint
import sys

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import title, __version__
from pan_chainguard.ccadb import (revoked, valid_from_to,
                                  derived_trust_bits, TrustBits, TrustBitsMap2)


DEFAULT_POLICY = {
    'sources': ['mozilla'],
    'operation': 'union',
    'trust_bits': [],
}

SOURCES_MAP = {
    'mozilla': 'Mozilla',
    'google': 'Google Chrome',
    'apple': 'Apple',
    'microsoft': 'Microsoft'
}

CCADB_MAP = {v: k for k, v in SOURCES_MAP.items()}

args = None


def main():
    global args
    args = parse_args()

    asyncio.run(main_loop())

    sys.exit(0)


async def main_loop():
    certs = read_certs()
    policy = get_policy()

    if args.debug > 1:
        print('total', len(certs), file=sys.stderr)
    if args.debug > 2:
        print(pprint.pformat(certs, width=160), file=sys.stderr)
    if args.verbose:
        print('policy:', policy)

    if args.stats:
        stats(certs, policy)
        return

    policy_certs = get_certs(certs, policy)

    if args.verbose:
        print("%s: %d total certificates" % (
            ', '.join(policy['sources']), len(policy_certs)))

    if args.fingerprints is not None:
        write_fingerprints(certs, policy_certs)


def read_certs():
    certs = {}

    try:
        with open(args.ccadb, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile,
                                    dialect='unix')
            for row in reader:
                if row['Certificate Record Type'] != 'Root Certificate':
                    continue

                sha256 = row['SHA-256 Fingerprint']
                name = row['Certificate Name']

                ret, err = revoked(row)
                if ret:
                    x = '%s %s %s' % (err, sha256, name)
                    if args.debug > 2:
                        print(x, file=sys.stderr)
                    continue

                ret, err = valid_from_to(row)
                if not ret:
                    x = '%s %s %s' % (err, sha256, name)
                    if args.debug > 2:
                        print(x, file=sys.stderr)
                    continue

                certs[sha256] = row

    except OSError as e:
        print('%s: %s' % (args.ccadb, e), file=sys.stderr)
        sys.exit(1)

    return certs


def get_policy():
    def isvalid(policy):
        if not isinstance(policy['sources'], list):
            x = '"sources" not list'
        elif not len(policy['sources']):
            x = '"sources" empty'
        elif not all(item in SOURCES_MAP for item in policy['sources']):
            x = 'Invalid "sources"'
        elif policy['operation'] not in ['union', 'intersection']:
            x = 'Invalid "operation"'
        elif not all(item in TrustBitsMap2
                     for item in policy['trust_bits']):
            x = 'Invalid "trust_bits"'
        else:
            return True, None

        return False, x

    if args.policy is None:
        return DEFAULT_POLICY

    if os.path.isfile(args.policy):
        try:
            with open(args.policy, 'r') as f:
                x = json.load(f)
        except (OSError, ValueError) as e:
            print('%s: %s' % (args.policy, e), file=sys.stderr)
            sys.exit(1)

    else:
        try:
            x = json.loads(args.policy)
        except ValueError as e:
            print('%s: %s' % (e, args.policy), file=sys.stderr)
            sys.exit(1)

    if 'sources' not in x:
        x['sources'] = DEFAULT_POLICY['sources']
    if 'operation' not in x:
        x['operation'] = DEFAULT_POLICY['operation']
    if 'trust_bits' not in x:
        x['trust_bits'] = DEFAULT_POLICY['trust_bits']

    ret, e = isvalid(x)

    if not ret:
        msg = '%s: ' % args.policy if os.path.isfile(args.policy) else ''
        msg += '%s: %s' % (e, x)
        print(msg, file=sys.stderr)
        sys.exit(1)

    return x


def get_certs(certs, policy):
    certs_ = []

    for row in certs.values():
        sha256 = row['SHA-256 Fingerprint']

        if policy_match(policy, row):
            certs_.append(sha256)

    return certs_


def stats(certs, policy):
    sources = {}
    for x in SOURCES_MAP.keys():
        policy_ = {
            'sources': [x],
            'trust_bits': policy['trust_bits'],
            'operation': policy['operation'],
        }
        source_certs = get_certs(certs, policy_)

        sources[x] = set(source_certs)

    sets = []
    for x in sources.keys():
        print("%s: %d total certificates" % (x, len(sources[x])))
        sets.append(set(sources[x]))

    x = ', '.join(SOURCES_MAP.keys())

    intersection = set.intersection(*sets)
    print('%s: %d total certificates in all (intersection)' % (
        x, len(intersection)))

    union = set.union(*sets)
    print('%s: %d total certificates in any (union)' % (
        x, len(union)))


def policy_match(policy, row):
    def sources_match(source_cert, source_pol):
        if not source_cert:
            return False

        if policy['operation'] == 'union':
            for x in source_pol:
                if x in source_cert:
                    return True
            return False
        elif policy['operation'] == 'intersection':
            for x in source_pol:
                if x not in source_cert:
                    return False
            return True
        else:
            assert False, 'Invalid operation: %s' % policy['operation']

    def trust_bits_match(bits_cert, bits_pol):
        if bits_cert == TrustBits.NONE:
            return True

        for x in bits_pol:
            if TrustBitsMap2[x] not in bits_cert:
                return False
        return True

    certificate_name = row['Certificate Name']
    sha256 = row['SHA-256 Fingerprint']

    status_root = row['Status of Root Cert']
    ccadb_status = status_root.split(';')
    included = [x for x in ccadb_status if ': Included' in x]

    ccadb_sources = [x.split(':')[0].strip() for x in included]
    sources = [CCADB_MAP[x] for x in ccadb_sources if x in CCADB_MAP]

    trust_bits = derived_trust_bits(row)

    if args.debug > 1:
        print(certificate_name,
              'sources', sources,
              'trust-bits', trust_bits, file=sys.stderr)

    if (sources_match(sources, policy['sources']) and
       trust_bits_match(trust_bits, policy['trust_bits'])):
        return True

    if args.debug > 1:
        print('no match', certificate_name, sha256, file=sys.stderr)

    return False


def write_fingerprints(certs, policy_certs):
    # duplicate PAN-OS
    def canonicalize(x):
        x = ''.join(c for c in x if ord(c) < 128)
        x = x.replace(' ', '_')
        x = x.replace(',', '_')

        return x

    fieldnames = [
        'filename',
        'sha256',
    ]

    try:
        with open(args.fingerprints, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile,
                                    dialect='unix',
                                    fieldnames=fieldnames)
            writer.writeheader()
            sequence = 9000
            for k in policy_certs:
                row = {}
                row['sha256'] = k
                sequence += 1
                name = certs[k]['Certificate Name']
                row['filename'] = '%04d_%s' % (sequence,
                                               canonicalize(name))
                writer.writerow(row)

    except OSError as e:
        print('%s: %s' % (args.fingerprints, e), file=sys.stderr)
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='create custom root store from CCADB')
    # curl -OJ \
    # https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2
    parser.add_argument('-c', '--ccadb',
                        required=True,
                        metavar='PATH',
                        help='CCADB AllCertificateRecordsCSVFormatv2 CSV path')
    parser.add_argument('-f', '--fingerprints',
                        metavar='PATH',
                        help='root store fingerprints CSV path')
    parser.add_argument('--policy',
                        metavar='JSON',
                        help='JSON policy object path or string')
    parser.add_argument('--stats',
                        action='store_true',
                        help='print source stats')
    parser.add_argument('--verbose',
                        action='store_true',
                        help='enable verbosity')
    parser.add_argument('--debug',
                        type=int,
                        choices=[0, 1, 2, 3],
                        default=0,
                        help='enable debug')
    x = '%s %s' % (title, __version__)
    parser.add_argument('--version',
                        action='version',
                        help='display version',
                        version=x)
    args = parser.parse_args()

    if args.debug:
        print(args, file=sys.stderr)

    return args


if __name__ == '__main__':
    main()
