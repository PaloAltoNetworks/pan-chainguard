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
import io
import os
import pprint
import sys
import tarfile
import time

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import title, __version__
from pan_chainguard.ccadb import *
from pan_chainguard.crtsh import ArgsError, CrtShApi

ROOT = 'root'
INTERMEDIATE = 'intermediate'
MAX_TASKS = 3  # concurrent crt.sh API requests
CRT_SH_TIMEOUT = 60

args = None


def main():
    global args
    args = parse_args()

    ret = asyncio.run(main_loop())

    sys.exit(ret)


async def main_loop():
    create_archive(test=True)

    certs, invalid, warning, roots, intermediates, parents = get_certs()
    if args.debug:
        print('roots %d, intermediates %d, parents %d' %
              (len(roots), len(intermediates), len(parents)))

    chains = get_cert_chains(roots, intermediates, parents)
    if args.debug > 1:
        print('chains %d (root=>intermediates)' % len(chains),
              pprint.pformat(chains),
              file=sys.stderr)

    total, total_invalid, panos = await get_panos_intermediates(
        certs, chains, invalid, warning)
    print('%d invalid certificates found' % total_invalid)
    print('%d intermediate chains found for %d root CAs' % (
        len(panos), total))
    if args.debug > 1:
        print('intermediate chains', pprint.pformat(panos),
              file=sys.stderr)

    errors, certificates = await get_cert_files(panos)
    if errors:
        print('Error: %d certificates were not downloaded' % errors)
    else:
        print('All %d certificate chains were downloaded successfully'
              % len(certificates))

    if args.debug > 2:
        print('certificates', pprint.pformat(certificates),
              file=sys.stderr)

    create_archive(certificates)

    return 2 if errors else 0


def get_certs():
    invalid = {}
    warning = {}
    roots = []
    intermediates = []
    parents = defaultdict(list)
    certs = {}
    duplicates = defaultdict(list)

    try:
        with open(args.ccadb, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile,
                                    dialect='unix')
            for row in reader:
                sha256 = row['SHA-256 Fingerprint']
                name = row['Certificate Name']

                ret, err = revoked(row)
                if ret:
                    x = '%s %s %s' % (err, sha256, name)
                    if args.debug > 1:
                        print(x, file=sys.stderr)
                    invalid[sha256] = x
                    continue

                ret, err = valid_from_to(row)
                if not ret:
                    x = '%s %s %s' % (err, sha256, name)
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
                    warning[sha256] = x

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
                        if args.debug > 1:
                            print(x, file=sys.stderr)
                            invalid[sha256] = x
                        continue

                    intermediates.append(sha256)
                    parents[parent_sha256].append(sha256)

    except OSError as e:
        print('%s: %s' % (args.ccadb, e), file=sys.stderr)
        sys.exit(1)

    if args.debug:
        for sha256 in duplicates:
            print('Duplicate certificates %s' % sha256, file=sys.stderr)
            for x in duplicates[sha256]:
                print('  %s %s %s' % (x['Certificate Name'],
                                      x['Certificate Record Type'],
                                      x['Salesforce Record ID']),
                      file=sys.stderr)

    return certs, invalid, warning, roots, intermediates, parents


def get_cert_chains(roots, intermediates, parents):
    chains = {}

    for k in roots:
        if k not in parents:
            if args.debug:
                print('Root with no child %s' % k,
                      file=sys.stderr)
            continue

        for child in parents[k]:
            chain = [k]
            follow(chain, child, parents)
            if args.debug > 1:
                print('chain[%d]:' % len(chain),
                      pprint.pformat(chain), file=sys.stderr)

        chains[chain[0]] = chain

    return chains


def follow(chain, k, parents):
    if args.debug > 1:
        print('follow[%d]:' % len(chain), k, file=sys.stderr)

    chain.append(k)
    if k in parents:
        for child in parents[k]:
            follow(chain, child, parents)


async def get_panos_intermediates(certs, chains, invalid, warning):
    intermediates = {}
    not_in_common_store = {}
    total = 0
    total_invalid = 0

    if args.fingerprints:
        try:
            with open(args.fingerprints, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile,
                                        dialect='unix')
                for row in reader:
                    sha256 = row['sha256']

                    if sha256 in warning:
                        print('Certificate warning %s: %s' % (
                            row['filename'],
                            warning[sha256]), file=sys.stderr)

                    if sha256 in invalid:
                        print('Invalid certificate %s: %s' % (
                            row['filename'],
                            invalid[sha256]), file=sys.stderr)
                        total_invalid += 1
                        continue

                    if sha256 not in certs:
                        print('Invalid certificate %s: %s' % (
                            row['filename'],
                            'Not found in CCADB'), file=sys.stderr)
                        total_invalid += 1
                        continue
                    else:
                        status_root = certs[sha256]['Status of Root Cert']
                        statuses = status_root.split(';')
                        included = [': Included' in x for x in statuses]
                        if not any(included):
                            not_in_common_store[sha256] = status_root
                            print('Certificate not in common root store'
                                  ' %s: %s' % (row['filename'], status_root),
                                  file=sys.stderr)

                    total += 1
                    if sha256 in chains:
                        intermediates[row['filename']] = [(ROOT, sha256)]
                        for x in chains[sha256][1:]:
                            intermediates[row['filename']].append(
                                (INTERMEDIATE, x))
                    elif args.verbose:
                        x = '%s %s' % (row['filename'], 'intermediates 0')
                        if sha256 in not_in_common_store:
                            x += ' (not in common root store)'
                        print(x, file=sys.stderr)

        except OSError as e:
            print('%s: %s' % (args.fingerprints, e), file=sys.stderr)
            sys.exit(1)

    return total, total_invalid, intermediates


async def download(api, sequence, sha256):
    tries = 0
    MAX_TRIES = 5
    RETRY_SLEEP = 5.0

    RETRY_STATUS = [
        429,  # Too Many Requests
        502,  # Bad Gateway
        503,  # Service Unavailable
        504,  # Gateway Time-out
    ]

    while True:
        tries += 1
        try:
            resp = await api.download(id=sha256[1])

            if resp.status in RETRY_STATUS:
                x = '%d %s %s %s' % (
                    resp.status, resp.reason, sequence, sha256[1])
                if tries == MAX_TRIES:
                    print('no retry after try %d %s' % (tries, x),
                          file=sys.stderr)
                    x = 'download failed ' + x
                    break
                print('retry after try %d %s' % (tries, x),
                      file=sys.stderr)
                await asyncio.sleep(RETRY_SLEEP)
            elif resp.status != 200:
                x = 'download failed %d %s %s %s' % (
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
                        print('no retry after try %d %s' % (tries, x),
                              file=sys.stderr)
                        x = 'download failed ' + x
                        break
                    print('retry after try %d %s' % (tries, x),
                          file=sys.stderr)
                    await asyncio.sleep(RETRY_SLEEP)

        except (asyncio.TimeoutError,
                asyncio.CancelledError,  # XXX
                aiohttp.ClientError) as e:
            msg = e if str(e) else type(e).__name__
            x = 'CrtShApi: %s %s %s' % (msg, sequence, sha256[1])
            if tries == MAX_TRIES:
                print('no retry after try %d %s' % (tries, x),
                      file=sys.stderr)
                x = 'download failed ' + x
                break
            print('retry after try %d %s' % (tries, x),
                  file=sys.stderr)
            # no sleep

        except ArgsError as e:
            x = 'CrtShApi: %s' % e
            break

    return None, x, None, None


async def get_cert_files(panos):
    user_agent = '%s/%s' % (title, __version__)
    headers = {'user-agent': user_agent}

    try:
        api = CrtShApi(timeout=CRT_SH_TIMEOUT, headers=headers)
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
        if args.verbose:
            print('download %s intermediates %d' % (
                sequence_friendly,
                len(roots[sequence][1:])))

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

    if args.debug:
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

    if args.debug:
        print('running %d tasks' % len(tasks),
              file=sys.stderr)
        start = time.time()

    for coro in asyncio.as_completed(tasks):
        filename, content, sequence, cert_type = await coro
        if filename is None:
            # error
            print(content, file=sys.stderr)
            errors += 1
        else:
            certificates[sequence].append((cert_type, filename, content))

    if args.debug:
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
        description='generate intermediate CAs to preload')
    # curl -OJ \
    # https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2
    parser.add_argument('-c', '--ccadb',
                        required=True,
                        metavar='PATH',
                        help='CCADB AllCertificateRecordsCSVFormatv2 CSV path')
    # sh cert-fingerprints.sh cert-dir
    parser.add_argument('-f', '--fingerprints',
                        metavar='PATH',
                        help='root CAs fingerprints CSV path')
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
