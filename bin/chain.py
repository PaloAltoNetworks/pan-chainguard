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
from collections import defaultdict
import csv
import json
import os
import sys
from treelib import Node, Tree

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import title, __version__
from pan_chainguard.ccadb import *
import pan_chainguard.util

args = None


def main():
    global args
    args = parse_args()

    ret = asyncio.run(main_loop())

    sys.exit(ret)


async def main_loop():
    certs, invalid, warning = get_certs()

    tree = get_tree(certs)
    if args.debug > 2:
        x = tree.show(stdout=False)
        print(x, file=sys.stderr, end='')

    total_invalid, newtree, intermediates = get_intermediates(
        tree, invalid, warning)

    if args.debug:
        x = newtree.show(stdout=False)
        print(x, file=sys.stderr, end='')

    write_fingerprints(intermediates)
    write_tree(newtree)

    return 0


def get_certs():
    invalid = {}
    warning = {}
    certs = {}
    duplicates = defaultdict(list)

    try:
        with open(args.ccadb, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile,
                                    dialect='unix')
            for row in reader:
                sha256 = row['SHA-256 Fingerprint']
                name = row['Certificate Name']
                cert_type = row['Certificate Record Type']
                parent_sha256 = row['Parent SHA-256 Fingerprint']

                ret, err = revoked(row)
                if ret:
                    x = '%s %s %s' % (err, sha256, name)
                    if args.debug > 2:
                        print(x, file=sys.stderr)
                    invalid[sha256] = x
                    continue

                ret, err = valid_from_to(row)
                if not ret:
                    x = '%s %s %s' % (err, sha256, name)
                    if args.debug > 2:
                        print(x, file=sys.stderr)
                    invalid[sha256] = x
                    continue

                if sha256 in certs:
                    if sha256 not in duplicates:
                        duplicates[sha256].append(certs[sha256])
                    duplicates[sha256].append(row)
                    continue

                if cert_type == 'Root Certificate':
                    if parent_sha256:
                        x = 'Root with parent: %s' % sha256
                        if args.debug > 1:
                            print(x, file=sys.stderr)
                        invalid[sha256] = x
                        continue

                if cert_type == 'Intermediate Certificate':
                    if not parent_sha256:
                        x = 'Intermediate with no parent: %s' % sha256
                        if args.debug > 1:
                            print(x, file=sys.stderr)
                        invalid[sha256] = x
                        continue

                    trust_bits = derived_trust_bits(row)
                    if (trust_bits != TrustBits.NONE and
                       TrustBits.SERVER_AUTHENTICATION not in trust_bits):
                        x = 'Missing %s in %s %s' % (
                            TrustBits.SERVER_AUTHENTICATION.name,
                            trust_bits, sha256)
                        if args.debug > 1:
                            print(x, file=sys.stderr)
                        invalid[sha256] = x
                        continue

                certs[sha256] = row

    except OSError as e:
        print('%s: %s' % (args.ccadb, e), file=sys.stderr)
        sys.exit(1)

    if args.debug > 1:
        for sha256 in duplicates:
            print('Duplicate certificates %s' % sha256, file=sys.stderr)
            for x in duplicates[sha256]:
                print('  %s %s %s' % (x['Certificate Name'],
                                      x['Certificate Record Type'],
                                      x['Salesforce Record ID']),
                      file=sys.stderr)

    return certs, invalid, warning


def get_tree(certs):
    nodes = {}

    for row in certs.values():
        sha256 = row['SHA-256 Fingerprint']
        name = row['Certificate Name']
        cert_type = row['Certificate Record Type']
        parent_name = row['Parent Certificate Name']

        tag = f'{sha256} Subject: "{name}"'
        if cert_type == 'Root Certificate':
            tag += f' CA-Owner: "{parent_name}"'
        else:
            tag += f' Issuer: "{parent_name}"'
        nodes[sha256] = Node(tag=tag, identifier=sha256, data=row)

    waiting_nodes = defaultdict(list)

    tree = Tree()
    tree.add_node(Node(tag='Root', identifier=0))

    for node in nodes.values():
        row = node.data
        sha256 = row['SHA-256 Fingerprint']
        parent_sha256 = row['Parent SHA-256 Fingerprint']

        if not parent_sha256:
            tree.add_node(nodes[sha256], parent=0)
        else:
            if tree.contains(parent_sha256):
                tree.add_node(nodes[sha256], parent=nodes[parent_sha256])
                # is node a parent for any waiting nodes
                if sha256 in waiting_nodes:
                    for x in waiting_nodes[sha256]:
                        tree.add_node(nodes[x], parent=nodes[sha256])
                    del waiting_nodes[sha256]
            else:
                # node's parent not in tree, add node to waiting list
                waiting_nodes[parent_sha256].append(sha256)

    if args.debug > 1 and waiting_nodes:
        print('Warning: nodes with no parent', file=sys.stderr)
        for x in waiting_nodes:
            print('parent', x, 'nodes', waiting_nodes[x], file=sys.stderr)

    return tree


def get_intermediates(tree, invalid, warning):
    intermediates = []
    total_invalid = 0

    try:
        data = pan_chainguard.util.read_fingerprints(
            path=args.root_fingerprints)
    except pan_chainguard.util.UtilError as e:
        print('%s: %s' % (args.root_fingerprints, e), file=sys.stderr)
        sys.exit(1)

    newtree = Tree()
    newtree.add_node(Node(tag='Root', identifier=0))

    for row in data:
        sha256 = row['sha256']

        if sha256 in warning:
            print('Certificate warning: %s' % (
                warning[sha256]), file=sys.stderr)

        if sha256 in invalid:
            print('Invalid certificate: %s' % (
                invalid[sha256]), file=sys.stderr)
            total_invalid += 1
            continue

        if not tree.contains(sha256):
            print('Not found in CCADB: %s' % (
                sha256), file=sys.stderr)
            total_invalid += 1
            continue

        node = tree.get_node(sha256)
        status_root = node.data['Status of Root Cert']
        statuses = status_root.split(';')
        included = [': Included' in x for x in statuses]
        if not any(included):
            print('Certificate not in common root store: '
                  '%s: %s' % (sha256, status_root),
                  file=sys.stderr)

        subtree = tree.subtree(sha256)
        nodes = subtree.all_nodes()
        for node in nodes[1:]:
            intermediates.append(node.identifier)
        for node in nodes:
            parent = subtree.parent(node.identifier)
            newtree.add_node(
                node=node,
                parent=0 if parent is None else parent.identifier)

        if args.debug > 1:
            print(subtree, end='', file=sys.stderr)
            nodes_ = [x.identifier for x in nodes]
            print(len(nodes_), nodes_, file=sys.stderr)

    return total_invalid, newtree, intermediates


def write_fingerprints(intermediates):
    if not args.int_fingerprints:
        return

    data = []
    for x in intermediates:
        row = {
            'type': 'intermediate',
            'sha256': x,
        }
        data.append(row)

    try:
        pan_chainguard.util.write_fingerprints(
            path=args.int_fingerprints,
            data=data)
    except pan_chainguard.util.UtilError as e:
        print('%s: %s' % (args.int_fingerprints, e), file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print('%d total intermediate certificates' % len(data))


def write_tree(tree):
    if not args.tree:
        return

    data = pan_chainguard.util.tree_to_dict(tree=tree)

    try:
        with open(args.tree, 'w') as f:
            json.dump(data, f, separators=(',', ':'))
    except (OSError, TypeError) as e:
        print('%s: %s' % (args.tree, e), file=sys.stderr)
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='determine intermediate CAs')
    # curl -OJ \
    # https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2
    parser.add_argument('-c', '--ccadb',
                        required=True,
                        metavar='PATH',
                        help='CCADB AllCertificateRecordsCSVFormatv2 CSV path')
    parser.add_argument('-r', '--root-fingerprints',
                        required=True,
                        metavar='PATH',
                        help='root CA fingerprints CSV path')
    parser.add_argument('-i', '--int-fingerprints',
                        metavar='PATH',
                        help='intermediate CA fingerprints CSV path')
    parser.add_argument('--tree',
                        metavar='PATH',
                        help='save certificate tree as JSON to path')
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
