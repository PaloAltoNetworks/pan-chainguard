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
import os
import sys
import time

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import title, __version__
from pan_chainguard.ccadb import *
from pan_chainguard.crtsh import ArgsError, CrtShApi
import pan_chainguard.mozilla
import pan_chainguard.util

MAX_TASKS = 3  # concurrent crt.sh API requests
CRT_SH_TIMEOUT = 60

args = None


def main():
    global args
    args = parse_args()

    ret = asyncio.run(main_loop())

    sys.exit(ret)


async def main_loop():
    if not pan_chainguard.util.is_writable(args.certs_new):
        print('%s: not writable' % args.certs_new, file=sys.stderr)
        sys.exit(1)

    fingerprints = []
    for x in args.fingerprints:
        try:
            fingerprints.extend(
                pan_chainguard.util.read_fingerprints(path=x))
        except pan_chainguard.util.UtilError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    mozilla = []
    if args.certs_mozilla:
        for x in args.certs_mozilla:
            try:
                mozilla.append(
                    pan_chainguard.mozilla.MozillaCaCerts(path=x))
            except pan_chainguard.mozilla.MozillaError as e:
                print(str(e), file=sys.stderr)
                sys.exit(1)

    certs_old = {}
    if args.certs_old:
        try:
            certs_old = pan_chainguard.util.read_cert_archive(
                path=args.certs_old)
        except pan_chainguard.util.UtilError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    errors, certs = await get_certs(fingerprints, mozilla, certs_old)

    try:
        pan_chainguard.util.write_cert_archive(
            path=args.certs_new, data=certs)
    except pan_chainguard.util.UtilError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print('Total certs-new: %d' % len(certs))

    return 2 if errors else 0


async def get_certs(fingerprints, mozilla, certs_old):
    certs = {}
    crtsh_download = {}
    total_certs_old = 0
    total_mozilla = {
        'MozillaIntermediateCerts': 0,
        'PublicAllIntermediateCerts': 0,
    }
    total_crtsh = 0

    for row in fingerprints:
        cert_type = row['type']
        sha256 = row['sha256']

        # may be duplicates in multiple fingerprint files
        if sha256 in certs:
            continue

        if sha256 in certs_old:
            total_certs_old += 1
            certs[sha256] = certs_old[sha256]
            continue

        if cert_type == 'intermediate':
            for mozilla_certs in mozilla:
                pem = mozilla_certs.get_cert_pem(sha256=sha256)
                if pem is not None:
                    total_mozilla[mozilla_certs.name] += 1
                    certs[sha256] = (cert_type, pem)
                    break
            if sha256 in certs:
                continue

        crtsh_download[sha256] = cert_type

    errors, certificates = await get_cert_files(crtsh_download.keys())
    for sha256 in certificates:
        total_crtsh += 1
        certs[sha256] = (crtsh_download[sha256], certificates[sha256])

    if args.verbose:
        print('certs-old: %d' % total_certs_old)
        for x in total_mozilla:
            print('%s: %d' % (x, total_mozilla[x]))
        print('crt.sh: %d' % total_crtsh)

    return errors, certs


async def download(api, sha256):
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
            if args.verbose and tries == 1:
                print('Download using crt.sh API %s' % sha256)

            resp = await api.download(id=sha256)

            if resp.status in RETRY_STATUS:
                x = '%d %s %s' % (
                    resp.status, resp.reason, sha256)
                if tries == MAX_TRIES:
                    print('no retry after try %d %s' % (tries, x),
                          file=sys.stderr)
                    x = 'download failed ' + x
                    break
                print('retry after try %d %s' % (tries, x),
                      file=sys.stderr)
                await asyncio.sleep(RETRY_SLEEP)
            elif resp.status != 200:
                x = 'download failed %d %s %s' % (
                    resp.status, resp.reason, sha256)
                break
            else:
                filename, content = await api.content(resp=resp)

                start = '-----BEGIN CERTIFICATE-----'
                end = '-----END CERTIFICATE-----\n'
                if (content.startswith(start) and
                   content.endswith(end)):
                    return content, sha256
                else:
                    # XXX ephemeral?
                    x = 'content malformed %s %s' % (
                        sha256, content)
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
            x = 'CrtShApi: %s %s' % (msg, sha256)
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

    return None, x


async def get_cert_files(sha256):
    user_agent = '%s/%s' % (title, __version__)
    headers = {'user-agent': user_agent}

    try:
        api = CrtShApi(timeout=CRT_SH_TIMEOUT, headers=headers)
    except ArgsError as e:
        print('CrtShApi: %s' % e, file=sys.stderr)
        sys.exit(1)
    else:
        errors, certificates = await download_certs(api, sha256)
    finally:
        await api.session.close()

    return errors, certificates


async def download_certs(api, sha256):
    certificates = {}
    tasks = []
    start = time.time()
    total = 0
    errors = 0

    for x in sha256:
        total += 1
        tasks.append(download(api, x))

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
        content, sha256 = await coro
        if content is None:
            # error
            print(sha256, file=sys.stderr)
            errors += 1
        else:
            certificates[sha256] = content

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


def parse_args():
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='get CA certificates')
    parser.add_argument('-f', '--fingerprints',
                        required=True,
                        action='append',
                        metavar='PATH',
                        help='CA fingerprints CSV path')
    parser.add_argument('-m', '--certs-mozilla',
                        action='append',
                        metavar='PATH',
                        help='Mozilla certs with PEM CSV path')
    parser.add_argument('--certs-old',
                        metavar='PATH',
                        help='old certificate archive path')
    parser.add_argument('--certs-new',
                        required=True,
                        metavar='PATH',
                        help='new certificate archive path')
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
