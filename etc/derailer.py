#!/usr/bin/env python3

#
# Copyright (c) 2025 Palo Alto Networks, Inc.
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
import hashlib
import os
from pathlib import Path
import re
import sys
import warnings

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.utils import CryptographyDeprecationWarning
except ImportError:
    print('Install cryptography: https://pypi.org/project/cryptography/',
          file=sys.stderr)
    sys.exit(1)

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import (title, __version__)
from pan_chainguard.ccadb import revoked, valid_from_to

args = None
downloads = {}


def main():
    global args
    args = parse_args()

    asyncio.run(main_loop())

    sys.exit(0)


async def main_loop():
    if args.debug:
        for k, v in vendors.items():
            if k == 'all':
                continue
            for x in v:
                print(k, x.__name__, x.url, file=sys.stderr)

    vendors_ = set(args.vendor)
    async with aiohttp.ClientSession() as session:
        urls = set([x.url for vendor in vendors_
                    for x in vendors[vendor]])
        tasks = [download(session, url) for url in urls]
        await asyncio.gather(*tasks)

    if args.debug > 1:
        for x in downloads:
            r, v = downloads[x]
            if not r:
                print(x, v, file=sys.stderr)
            else:
                print(x, len(v), file=sys.stderr)

    ccadb = None
    if args.ccadb:
        ccadb = load_ccadb(args.ccadb)

    if not args.debug:
        warnings.filterwarnings('ignore',
                                category=CryptographyDeprecationWarning)
    for k, v in vendors.items():
        if k in vendors_:
            for x in v:
                fingerprints = x()
                print(f'{x.__name__}: '
                      f'{len(fingerprints)} total certificates')
                if args.verbose:
                    check_validity(ccadb, fingerprints, x.__name__)
                if args.save:
                    directory = Path(args.save)
                    path = directory / f'{x.__name__}.txt'
                    digest = save(path, sorted(fingerprints))
                    if digest and args.verbose:
                        print(f'Saved fingerprints '
                              f'(SHA256 {digest}) to {path}')


async def download(session, url):
    try:
        async with session.get(url) as response:
            if response.status != 200:
                x = (f'Error: status code {response.status}')
                downloads[url] = False, x
                return
            content = await response.text()
            if args.verbose:
                print(f'Downloaded {len(content)} bytes from {url}')
    except aiohttp.ClientError as e:
        x = f'Request failed: {e}'
        downloads[url] = False, x
        return

    downloads[url] = True, content


def load_pem_cert(data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data)


def pem_cert_fingerprint(data: bytes) -> str:
    cert = x509.load_pem_x509_certificate(data)
    return cert.fingerprint(hashes.SHA256()).hex().upper()


def load_ccadb(path):
    ccadb = defaultdict(list)
    try:
        with open(args.ccadb, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile,
                                    dialect='unix')
            for row in reader:
                sha256 = row['SHA-256 Fingerprint']
                ccadb[sha256].append(row)

    except OSError as e:
        print('%s: %s' % (args.ccadb, e), file=sys.stderr)
        sys.exit(1)

    return ccadb


def check_validity(ccadb, fingerprints, vendor):
    if not ccadb:
        return

    for sha256 in fingerprints:
        if sha256 not in ccadb:
            print(f'{vendor}: {sha256} not in CCADB')
            continue

        row = ccadb[sha256][0]
        name = row['Certificate Name']
        cert_type = row['Certificate Record Type']

        x = 'Root Certificate'
        if len(ccadb[sha256]) == 1 and cert_type != x:
            err = f'Not a {x}'
            print(f'{vendor}: {err} {sha256} {name}')

        if len(ccadb[sha256]) > 1:
            err = f'{len(ccadb[sha256])} duplicates'
            print(f'{vendor}: {err} {sha256} {name}')

        ret, err = revoked(row)
        if ret:
            print(f'{vendor}: {err} {sha256} {name}')

        ret, err = valid_from_to(row)
        if not ret:
            print(f'{vendor}: {err} {sha256} {name}')


def save(path, fingerprints):
    data = '\n'.join(fingerprints) + '\n'
    try:
        with open(path, 'w') as f:
            f.write(data)
    except OSError as e:
        print(f'{path}: {e}', file=sys.stderr)
        return

    return hashlib.sha256(data.encode()).hexdigest()


def websites_trusted(vendor, row):
    def mozilla(row):
        ret = (row['Mozilla Status'] == 'Included' and
               'Websites' in row['Mozilla Trust Bits'].split(';'))
        return ret

    def microsoft(row):
        ret = (row['Microsoft Status'] == 'Included' and
               'Server Authentication' in row['Microsoft EKUs'].split(';'))
        return ret

    def chrome(row):
        ret = row['Google Chrome Status'] == 'Included'
        return ret

    def apple(row):
        ret = (row['Apple Status'] == 'Included' and
               'serverAuth' in row['Apple Trust Bits'].split(';'))
        return ret

    return locals()[vendor](row)


def set_url(url):
    def decorator(func):
        func.url = url
        return func
    return decorator


@set_url('https://ccadb.my.salesforce-sites.com/ccadb/'
         'AllIncludedRootCertsCSV')
def mozilla_0():
    url = mozilla_0.url
    r, data = downloads[url]
    if not r:
        print(f'{url}: {data}')
        return

    reader = csv.DictReader(data.splitlines())

    fingerprints = []
    for row in reader:
        if websites_trusted('mozilla', row):
            fingerprints.append(row['SHA-256 Fingerprint'])

    return fingerprints


@set_url('https://ccadb.my.salesforce-sites.com/mozilla/'
         'IncludedRootsDistrustTLSSSLPEMCSV?TrustBitsInclude=Websites')
def mozilla_1():
    url = mozilla_1.url
    r, data = downloads[url]
    if not r:
        print(f'{url}: {data}')
        return

    reader = csv.DictReader(data.splitlines())

    fingerprints = []
    for row in reader:
        pem = row.get('PEM')
        if pem:
            fingerprint = pem_cert_fingerprint(pem.encode())
            fingerprints.append(fingerprint)

    return fingerprints


@set_url('https://ccadb.my.salesforce-sites.com/ccadb/'
         'AllIncludedRootCertsCSV')
def microsoft_0():
    url = microsoft_0.url
    r, data = downloads[url]
    if not r:
        print(f'{url}: {data}')
        return

    reader = csv.DictReader(data.splitlines())

    fingerprints = []
    for row in reader:
        if websites_trusted('microsoft', row):
            fingerprints.append(row['SHA-256 Fingerprint'])

    return fingerprints


@set_url('https://ccadb.my.salesforce-sites.com/microsoft/'
         'IncludedRootsPEMCSVForMSFT?MicrosoftEKUs=Server Authentication')
def microsoft_1():
    url = microsoft_1.url
    r, data = downloads[url]
    if not r:
        print(f'{url}: {data}')
        return

    reader = csv.DictReader(data.splitlines())

    fingerprints = []
    for row in reader:
        pem = row.get('PEM')
        if pem:
            fingerprint = pem_cert_fingerprint(pem.encode())
            fingerprints.append(fingerprint)

    return fingerprints


@set_url('https://ccadb.my.salesforce-sites.com/microsoft/'
         'IncludedCACertificateReportForMSFTCSV')
def microsoft_2():
    url = microsoft_2.url
    r, data = downloads[url]
    if not r:
        print(f'{url}: {data}')
        return

    reader = csv.DictReader(data.splitlines())

    fingerprints = []
    for row in reader:
        status = row['Microsoft Status']
        if status != 'Included':
            continue
        sha256 = row['SHA-256 Fingerprint']
        trust_bits = row['Microsoft EKUs'].split(';')
        if 'Server Authentication' not in trust_bits:
            continue
        fingerprints.append(sha256)

    return fingerprints


@set_url('https://ccadb.my.salesforce-sites.com/ccadb/'
         'AllIncludedRootCertsCSV')
def chrome_0():
    url = chrome_0.url
    r, data = downloads[url]
    if not r:
        print(f'{url}: {data}')
        return

    reader = csv.DictReader(data.splitlines())

    fingerprints = []
    for row in reader:
        if websites_trusted('chrome', row):
            fingerprints.append(row['SHA-256 Fingerprint'])

    return fingerprints


@set_url('https://raw.githubusercontent.com/chromium/chromium/'
         'main/net/data/ssl/chrome_root_store/root_store.certs')
def chrome_1():
    url = chrome_1.url
    r, data = downloads[url]
    if not r:
        print(f'{url}: {data}')
        return

    PEM_PATTERN = re.compile(
        r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----',
        re.DOTALL
    )
    matches = PEM_PATTERN.findall(data)
    certs = [
        f'-----BEGIN CERTIFICATE-----{m}-----END CERTIFICATE-----'
        for m in matches
    ]

    fingerprints = []
    for pem in certs:
        fingerprint = pem_cert_fingerprint(pem.encode())
        fingerprints.append(fingerprint)

    return fingerprints


@set_url('https://ccadb.my.salesforce-sites.com/ccadb/'
         'AllIncludedRootCertsCSV')
def apple_0():
    url = apple_0.url
    r, data = downloads[url]
    if not r:
        print(f'{url}: {data}')
        return

    reader = csv.DictReader(data.splitlines())

    fingerprints = []
    for row in reader:
        if websites_trusted('apple', row):
            fingerprints.append(row['SHA-256 Fingerprint'])

    return fingerprints


vendors = {
    'mozilla': [mozilla_0, mozilla_1],
    'microsoft': [microsoft_0, microsoft_1, microsoft_2],
    'chrome': [chrome_0, chrome_1],
    'apple': [apple_0],
}
vendors['all'] = [x for vendor in vendors
                  for x in vendors[vendor]]


def parse_args():
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='vendor root CA program analysis')
    parser.add_argument('-V', '--vendor',
                        action='append',
                        required=True,
                        choices=vendors.keys(),
                        help='vendor')
    parser.add_argument('-s', '--save',
                        metavar='DIR',
                        help='save fingerprints to directory')
    # https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv3
    parser.add_argument('-c', '--ccadb',
                        metavar='PATH',
                        help='CCADB all certificate information CSV path')
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
