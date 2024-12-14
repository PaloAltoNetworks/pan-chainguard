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
import io
import logging
import os
import sys
import tarfile
import time

try:
    import pan.xapi
except ImportError:
    print('Install pan-python: https://pypi.org/project/pan-python/',
          file=sys.stderr)
    sys.exit(1)

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import (title, __version__)
from pan_chainguard.util import s1_in_s2

args = None


def main():
    global args
    args = parse_args()

    logger = logging.getLogger(pan.xapi.__name__)
    if args.xdebug == 3:
        logger.setLevel(pan.xapi.DEBUG3)
    elif args.xdebug == 2:
        logger.setLevel(pan.xapi.DEBUG2)
    elif args.xdebug == 1:
        logger.setLevel(pan.xapi.DEBUG1)

    log_format = '%(name)s: %(message)s'
    handler = logging.StreamHandler()
    formatter = logging.Formatter(log_format)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    asyncio.run(main_loop())

    sys.exit(0)


async def main_loop():
    try:
        xapi = pan.xapi.PanXapi(tag=args.tag,
                                debug=args.xdebug)
    except pan.xapi.PanXapiError as e:
        print('pan.xapi.PanXapi:', e, file=sys.stderr)
        sys.exit(1)

    create_archive(test=True)

    store = {}
    for cert_name, filename in get_trusted_certs(xapi):
        if args.verbose:
            print('Exporting %s => %s' % (cert_name, filename))
        _, content = export_cert(xapi, cert_name)
        if content is not None:
            store[filename] = content

    total = create_archive(store)
    print('Exported %d PAN-OS trusted CAs to %s' % (total, args.certs))


def get_trusted_certs(xapi):
    kwargs = {'xpath': '/config/predefined/trusted-root-ca/entry'}
    api_request(xapi, xapi.get, kwargs, 'success', '19')
    entries = xapi.element_root.findall('./result/entry')

    for entry in entries:
        name = entry.attrib['name']
        x = entry.find('./filename')
        filename = x.text
        yield name, filename


def export_cert(xapi, name):
    kwargs = {
        'category': 'certificate',
        'extra_qs': {
            'certificate-name': name,
            'format': 'pem',
            'include-key': 'no',
        },
    }
    api_request(xapi, xapi.export, kwargs, 'success')
    if xapi.export_result is None:
        print("Can't export %s" % name, file=sys.stderr)
        return None, None

    return xapi.export_result['file'], xapi.export_result['content']


def api_request(xapi, func, kwargs, status=None, status_code=None):
    try:
        func(**kwargs)
    except pan.xapi.PanXapiError as e:
        print('%s: %s: %s' % (func.__name__, kwargs, e),
              file=sys.stderr)
        sys.exit(1)

    if status is not None and not s1_in_s2(xapi.status, status):
        print('%s: %s: status %s != %s' %
              (func.__name__, kwargs,
               xapi.status, status),
              file=sys.stderr)
        sys.exit(1)

    if (status_code is not None and
       not s1_in_s2(xapi.status_code, status_code)):
        print('%s: %s: status_code %s != %s' %
              (func.__name__, kwargs,
               xapi.status_code, status_code),
              file=sys.stderr)
        sys.exit(1)


def create_archive(store=None, test=False):
    try:
        with tarfile.open(name=args.certs, mode='w:gz') as tar:
            if test:
                return
            total = 0
            for filename in sorted(store.keys()):
                member = tarfile.TarInfo(name=filename)
                member.size = len(store[filename])
                member.mtime = time.time()
                f = io.BytesIO(store[filename])
                tar.addfile(member, fileobj=f)
                total += 1
    except (tarfile.TarError, OSError) as e:
        print("tarfile %s: %s" % (args.certs, e), file=sys.stderr)
        sys.exit(1)

    return total


def parse_args():
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='export PAN-OS trusted CAs')
    parser.add_argument('--tag', '-t',
                        required=True,
                        help='.panrc tagname')
    x = 'root-store.tgz'
    parser.add_argument('--certs',
                        default=x,
                        metavar='PATH',
                        help='PAN-OS trusted CAs archive path'
                        ' (default: %s)' % x)
    parser.add_argument('--xdebug',
                        type=int,
                        choices=[0, 1, 2, 3],
                        default=0,
                        help='pan.xapi debug')
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
