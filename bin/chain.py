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

import aiohttp
import argparse
import asyncio
from collections import defaultdict
import csv
import datetime
import io
import os
import pprint
import sys
import tarfile
import time

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import (title, __version__)
from pan_chainguard.crtsh import (ArgsError, CrtShApi)

ROOT = 'root'
INTERMEDIATE = 'intermediate'
MAX_TASKS = 3  # concurrent crt.sh API requests
CRT_SH_TIMEOUT = 60

args = None


def main():
    global args
    args = parse_args()

    asyncio.run(main_loop())

    sys.exit(0)


async def main_loop():
    create_archive(test=True)

    invalid, roots, intermediates, parents = get_certs()
    if args.verbose:
        print('roots %d, intermediates %d, parents %d' %
              (len(roots), len(intermediates), len(parents)))

    chains = get_cert_chains(roots, intermediates, parents)
    if args.verbose:
        print('chains %d (root=>intermediates)' % len(chains),
              pprint.pformat(chains),
              file=sys.stderr)

    total, total_invalid, panos = await get_panos_intermediates(
        chains, invalid)
    print('%d intermediate chains found for %d PAN-OS trusted CAs' % (
        len(panos), total))
    if args.verbose:
        print('PAN-OS intermediate chains', pprint.pformat(panos),
              file=sys.stderr)

    errors, certificates = await get_cert_files(panos)
    if errors:
        print('Warning: %d certificates were not downloaded')

    if False and args.verbose:
        print('PAN-OS certificates', pprint.pformat(certificates),
              file=sys.stderr)

    create_archive(certificates)


def get_certs():
    invalid = {}
    roots = []
    intermediates = []
    parents = defaultdict(list)
    certs = {}
    duplicates = defaultdict(list)

    now = datetime.datetime.now(datetime.timezone.utc)

    try:
        with open(args.ccadb, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile,
                                    dialect='unix')
            for row in reader:
                sha256 = row['SHA-256 Fingerprint']

                if row['Revocation Status'] not in ['', 'Not Revoked']:
                    x = '%s %s %s' % (row['Revocation Status'],
                                      sha256,
                                      row['Certificate Name'])
                    if args.verbose:
                        print(x, file=sys.stderr)
                    invalid[sha256] = x
                    continue

                fmt = '%Y.%m.%d %z'
                valid_from = datetime.datetime.strptime(
                    row['Valid From (GMT)'] + ' +0000', fmt)
                valid_to = datetime.datetime.strptime(
                    row['Valid To (GMT)'] + ' +0000', fmt)
                if now < valid_from:
                    x = 'Not yet valid (valid from %s) %s %s' % (
                        row['Valid From (GMT)'],
                        sha256,
                        row['Certificate Name'])
                    if args.verbose:
                        print(x, file=sys.stderr)
                    invalid[sha256] = x
                    continue

                if valid_to < now:
                    x = 'Expired (valid to %s) %s %s' % (
                        row['Valid To (GMT)'],
                        sha256,
                        row['Certificate Name'])
                    if args.verbose:
                        print(x, file=sys.stderr)
                    invalid[sha256] = x
                    continue

                derived_trust_bits = row['Derived Trust Bits']
                if (derived_trust_bits and 'Server Authentication' not in
                   derived_trust_bits.split(';')):
                    x = 'Missing Server Authentication %s' % sha256
                    invalid[sha256] = x
                    continue

                cert_type = row['Certificate Record Type']

                if sha256 in certs:
                    if sha256 not in duplicates:
                        duplicates[sha256].append(certs[sha256])
                    duplicates[sha256].append(row)
                    continue

                certs[sha256] = row

                if cert_type == 'Root Certificate':
                    roots.append(sha256)

                if cert_type == 'Intermediate Certificate':
                    parent_sha256 = row['Parent SHA-256 Fingerprint']
                    if not parent_sha256:
                        x = 'Intermediate with no parent: %s' % sha256
                        if args.verbose:
                            print(x, file=sys.stderr)
                            invalid[sha256] = x
                        continue

                    intermediates.append(sha256)
                    parents[parent_sha256].append(sha256)

    except OSError as e:
        print('%s: %s' % (args.ccadb, e), file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        for sha256 in duplicates:
            print('Duplicate certificates %s' % sha256, file=sys.stderr)
            for x in duplicates[sha256]:
                print('  %s %s %s' % (x['Certificate Name'],
                                      x['Certificate Record Type'],
                                      x['Salesforce Record ID']),
                      file=sys.stderr)

    return invalid, roots, intermediates, parents


def get_cert_chains(roots, intermediates, parents):
    chains = {}

    for k in roots:
        if k not in parents:
            if args.verbose:
                print('Root with no child %s' % k,
                      file=sys.stderr)
            continue

        for child in parents[k]:
            chain = [k]
            follow(chain, child, parents)
            if args.verbose:
                print('chain[%d]:' % len(chain),
                      pprint.pformat(chain), file=sys.stderr)

        chains[chain[0]] = chain

    return chains


def follow(chain, k, parents):
    if args.verbose:
        print('follow[%d]:' % len(chain), k, file=sys.stderr)

    chain.append(k)
    if k in parents:
        for child in parents[k]:
            follow(chain, child, parents)


async def get_panos_intermediates(chains, invalid):
    intermediates = {}
    total = 0
    total_invalid = 0

    if args.fingerprints:
        try:
            with open(args.fingerprints, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile,
                                        dialect='unix')
                for row in reader:
                    sha256 = row['sha256']
                    if sha256 in invalid:
                        print('Invalid PAN-OS certificate %s: %s' % (
                            row['filename'],
                            invalid[sha256]))
                        total_invalid += 1
                        continue

                    total += 1
                    if sha256 in chains:
                        intermediates[row['filename']] = [(ROOT, sha256)]
                        for x in chains[sha256][1:]:
                            intermediates[row['filename']].append(
                                (INTERMEDIATE, x))

        except OSError as e:
            print('%s: %s' % (args.ccadb, e), file=sys.stderr)
            sys.exit(1)

    return total, total_invalid, intermediates


async def download(api, sequence, sha256):
    tries = 0
    MAX_TRIES = 5
    RETRY_SLEEP = 5.0

    while True:
        tries += 1
        try:
            resp = await api.download(id=sha256[1])

            if resp.status == 429:
                x = '%d %s' % (resp.status, resp.reason)
                if tries == MAX_TRIES:
                    print('no retry after try %d, %s' % (tries, x),
                          file=sys.stderr)
                    break
                print('retry after try %d, %s' % (tries, x),
                      file=sys.stderr)
                await asyncio.sleep(RETRY_SLEEP)
            elif resp.status != 200:
                x = 'download %d %s %s %s' % (
                    resp.status, resp.reason, sequence, sha256[1])
                break
            else:
                filename, content = await api.content(resp=resp)
                if filename is None:
                    filename = sha256[1] + '.crt'

                start = '-----BEGIN CERTIFICATE-----'
                end = '-----END CERTIFICATE-----\n'
                if (content.startswith(start) and
                   content.endswith(end)):
                    return filename, content, sequence, sha256[0]
                else:
                    # XXX ephemeral?
                    x = 'content malformed %s %s %s' % (
                        sequence, sha256[1], content)
                    if tries == MAX_TRIES:
                        print('no retry after try %d, %s' % (tries, x),
                              file=sys.stderr)
                        break
                    print('retry after try %d, %s' % (tries, x),
                          file=sys.stderr)
                    await asyncio.sleep(RETRY_SLEEP)

        except (asyncio.TimeoutError,
                asyncio.CancelledError,  # XXX
                aiohttp.ClientError) as e:
            msg = e if str(e) else type(e).__name__
            x = 'CrtShApi: %s: %s %s' % (msg, sequence, sha256[1])
            if tries == MAX_TRIES:
                print('no retry after try %d, %s' % (tries, x),
                      file=sys.stderr)
                break
            print('retry after try %d, %s' % (tries, x),
                  file=sys.stderr)
            # no sleep

        except ArgsError as e:
            x = 'CrtShApi: %s' % e
            break

    return None, x, None, None


async def get_cert_files(panos):
    try:
        api = CrtShApi(timeout=CRT_SH_TIMEOUT)
    except ArgsError as e:
        print('CrtShApi: %s' % e, file=sys.stderr)
        sys.exit(1)
    else:
        errors, certificates = await process_roots(api, panos)
    finally:
        await api.session.close()

    return errors, certificates


async def process_roots(api, roots):
    certificates = defaultdict(list)
    tasks = []
    start = time.time()
    total = 0
    errors = 0

    for sequence in roots:
        sequence_friendly = sequence
        if sequence.endswith('.cer'):
            sequence_friendly = sequence[:-4]
        print('download CA %s intermediates %d' % (sequence_friendly,
                                                   len(roots[sequence][1:])),
              flush=True)

        for sha256 in roots[sequence]:
            if not args.roots and sha256[0] == ROOT:
                continue
            total += 1
            tasks.append(download(api, sequence_friendly, sha256))

            if len(tasks) == MAX_TASKS:
                errors += await run_tasks(tasks, certificates)
                tasks = []

    if len(tasks):
        errors += await run_tasks(tasks, certificates)

    if args.verbose:
        end = time.time()
        elapsed = end - start
        mins = elapsed // 60
        secs = elapsed % 60
        avg = elapsed / total if total > 0 else 0
        print('%d tasks, elapsed %.2f seconds, %dm%ds, avg %.2fs' %
              (total, elapsed, mins, secs, avg),
              file=sys.stderr)

    return errors, certificates


async def run_tasks(tasks, certificates):
    INTERVAL_WAIT = 3.3  # random throttle sweet spot to avoid TimeoutError
    errors = 0

    if args.verbose:
        print('running %d tasks' % len(tasks),
              file=sys.stderr)
        start = time.time()

    for coro in asyncio.as_completed(tasks):
        filename, content, sequence, cert_type = await coro
        if filename is None:
            # error
            print(content)
            errors += 1
        else:
            certificates[sequence].append((cert_type, filename, content))

    if args.verbose:
        end = time.time()
        elapsed = end - start
        rate = len(tasks) / elapsed
        rate2 = elapsed / len(tasks)
        print('%d tasks complete, elapsed %.2f seconds, '
              '%.2f tasks/sec, %.2f secs/task' %
              (len(tasks), elapsed, rate, rate2), file=sys.stderr)
        print('sleeping %.2fs' % INTERVAL_WAIT, file=sys.stderr)
        await asyncio.sleep(INTERVAL_WAIT)

    return errors


def create_archive(certificates=None, test=False):
    if not certificates:
        return

    try:
        with tarfile.open(name=args.certs, mode='w:gz') as tar:
            if test:
                os.unlink(args.certs)
                return
            for sequence in sorted(certificates.keys()):
                for cert in certificates[sequence]:
                    name = os.path.join(sequence, cert[0], cert[1])
                    member = tarfile.TarInfo(name=name)
                    member.size = len(cert[2])
                    member.mtime = time.time()
                    f = io.BytesIO(cert[2].encode())
                    tar.addfile(member, fileobj=f)
    except (tarfile.TarError, OSError) as e:
        print("tarfile %s: %s" % (args.certs, e), file=sys.stderr)
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='generate PAN-OS intermediate CAs to preload')
    # curl -OJ \
    # https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2
    parser.add_argument('-c', '--ccadb',
                        required=True,
                        metavar='PATH',
                        help='CCADB AllCertificateRecordsCSVFormatv2 CSV path')
    # sh cert-fingerprints.sh cert-dir
    parser.add_argument('-f', '--fingerprints',
                        metavar='PATH',
                        help='PAN-OS trusted CAs fingerprints CSV path')
    x = 'certificates.tgz'
    parser.add_argument('--certs',
                        default=x,
                        metavar='PATH',
                        help='certificate archive path'
                        ' (default: %s)' % x)
    parser.add_argument('--roots',
                        action='store_true',
                        help='also download root CAs (experimental)')
    parser.add_argument('--verbose',
                        action='store_true',
                        help='enable verbosity')
    x = '%s %s' % (title, __version__)
    parser.add_argument('--version',
                        action='version',
                        help='display version',
                        version=x)
    args = parser.parse_args()

    if args.verbose:
        print(args, file=sys.stderr)

    return args


if __name__ == '__main__':
    main()
