#!/usr/bin/env python3

#
# Copyright (c) 2026 Palo Alto Networks, Inc.
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
import base64
import csv
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import pprint
import sys
from treelib import Tree
from typing import Optional, Tuple, Union
import warnings

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.utils import CryptographyDeprecationWarning
except ImportError:
    print('Install cryptography: https://pypi.org/project/cryptography/',
          file=sys.stderr)
    sys.exit(1)

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import title, __version__
from pan_chainguard.ccadb import (CcadbRootTrustSettings, CcadbError,
                                  RootStatusBits, TrustBits,
                                  revoked, valid_from_to, derived_trust_bits)
from pan_chainguard.mozilla import MozillaError, MozillaOneCrl
import pan_chainguard.util

DOWNLOAD_TIMEOUT = 30.0  # total
MOZ = 'mozilla'
args = None


@dataclass(frozen=True)
class InputSpec:
    dest: str
    label: str
    url: str
    path: Optional[Path]


@dataclass(frozen=True)
class MozillaIntermediate:
    record: dict
    cert: x509.Certificate
    sha256: str


def main():
    global args
    args, specs = parse_args()

    if not args.debug:
        warnings.filterwarnings('ignore',
                                category=CryptographyDeprecationWarning)
#        warnings.filterwarnings('ignore', category=UserWarning)

    status = asyncio.run(main_loop(specs))

    sys.exit(status)


async def main_loop(specs):
    outputs, errors = await resolve_inputs(args, specs)
    if errors:
        return 1

    trust = load_root_trust(outputs['trust_settings'])
    onecrl = load_onecrl(outputs['onecrl'])
    ccadb_certs = load_ccadb_certs(outputs['ccadb'])

    cg_tree = load_cert_tree(outputs['tree'])
    cg_moz_tree = mozilla_tree(cg_tree, trust)

    cg_certs = load_cert_archive(outputs['certs'])
    cg_moz_certs = certs_in_tree(cg_certs, cg_moz_tree, MOZ)
    cg_moz_certs_info = get_cert_info(cg_moz_certs)
    cg_moz_hash_index = build_hash_index(cg_moz_certs_info)

    moz_certs = load_moz_certs(outputs['moz_int'])

    r = await diff(onecrl, ccadb_certs, trust, moz_certs, cg_tree, cg_certs,
                   cg_moz_certs_info, cg_moz_hash_index)

    return r


def load_root_trust(input: bytes):
    try:
        trust = CcadbRootTrustSettings(source=input,
                                       debug=bool(args.debug))
    except CcadbError as e:
        print('CcadbRootTrustSettings: %s' % e, file=sys.stderr)
        sys.exit(1)

    return trust


def load_onecrl(input: bytes):
    try:
        onecrl = MozillaOneCrl(source=input,
                               debug=bool(args.debug))
    except MozillaError as e:
        print('MozillaOneCrl: %s' % e, file=sys.stderr)
        sys.exit(1)

    return onecrl


def load_ccadb_certs(input: bytes):
    certs = {}

    try:
        with pan_chainguard.util.open_csv_source(input) as csvfile:
            reader = csv.DictReader(csvfile, dialect='unix')
            fieldnames = set(reader.fieldnames or [])
            if 'SHA-256 Fingerprint' not in fieldnames:
                print('CCADB all certificates: Invalid CSV',
                      file=sys.stderr)
                sys.exit(1)

            for row in reader:
                sha256 = row['SHA-256 Fingerprint']
                certs.setdefault(sha256, []).append(row)
    except OSError as e:
        print('CCADB all certificates: %s' % e, file=sys.stderr)
        sys.exit(1)

    return certs


def load_cert_tree(input: bytes):
    try:
        data = json.loads(input)
    except ValueError as e:
        print('tree: %s' % e, file=sys.stderr)
        sys.exit(1)

    try:
        tree = pan_chainguard.util.dict_to_tree(data=data)
    except pan_chainguard.util.UtilError as e:
        print('tree: %s' % e, file=sys.stderr)
        sys.exit(1)

    return tree


def mozilla_tree(tree: Tree, trust) -> Tree:
    new_tree = Tree(tree, deep=True)

    for child in list(new_tree.children(new_tree.root)):
        sha256 = child.identifier
        status_bits = trust.root_status_bits_flag(sha256=sha256)
        if (status_bits is not None and
           RootStatusBits.MOZILLA in status_bits):
            trust_bits = trust.mozilla_trust_bits(sha256=sha256)
            if TrustBits.SERVER_AUTHENTICATION in trust_bits:
                continue

        new_tree.remove_node(child.identifier)  # removes entire subtree

    return new_tree


def load_cert_archive(input: bytes):
    try:
        data = pan_chainguard.util.read_cert_archive(
            fileobj=io.BytesIO(input))
    except pan_chainguard.util.UtilError as e:
        print('certs: %s' % e, file=sys.stderr)
        sys.exit(1)

    return data


def certs_in_tree(data, tree, label):
    new_data = {}

    for k, v in data.items():
        if tree.contains(k):
            new_data[k] = v

    if args.verbose:
        roots = 0
        intermediates = 0
        for x in new_data.values():
            if x[0] == 'root':
                roots += 1
            else:
                intermediates += 1
        print('%s %s roots %d intermediates %d' % (
            title, label, roots, intermediates))

    return new_data


def get_cert_info(data):
    certs = []

    for sha256 in data:
        cert_type, content = data[sha256]

        cert = load_pem_cert(content)
        if cert is None:
            continue

        fingerprint = fingerprint_sha256(cert)
        if fingerprint != sha256:
            print('fingerprint: archive %s != PEM %s' % (
                sha256, fingerprint), file=sys.stderr)

        x = {
            'cert': cert,
            'cert_fingerprint_sha256': sha256,
            'cert_type': cert_type,
            'cert_der_sha256_b64': der_sha256_b64(cert),
        }

        certs.append(x)

    return certs


def build_hash_index(certs):
    idx = {}

    for cert in certs:
        for k in ['cert_fingerprint_sha256',
                  'cert_der_sha256_b64']:
            if cert[k] in idx:
                raise ValueError(f'Hash collision/conflict for {cert[k]}')
            idx[cert[k]] = cert

    return idx


def load_moz_certs(input: bytes):
    try:
        data = json.loads(input)
    except ValueError as e:
        print('%s intermediates: %s' % (MOZ, e), file=sys.stderr)
        sys.exit(1)

    moz_certs = {}
    for x in data['data']:
        if x['derHash'] in moz_certs:
            print('Duplicate derHash: %s' % x['derHash'], file=sys.stderr)
        else:
            moz_certs[x['derHash']] = x

    if args.verbose:
        print('%s intermediates %d' % (MOZ, len(moz_certs)))

    return moz_certs


async def diff(onecrl, ccadb_certs, trust, moz_certs, cg_tree, cg_certs,
               cg_moz_certs_info, cg_moz_hash_index):
    r = 0

    missing = []
    for x in moz_certs:
        if x not in cg_moz_hash_index:
            missing.append(moz_certs[x])
        else:
            if cg_moz_hash_index[x]['cert_type'] == 'root':
                if args.debug:
                    print('%s intermediate also in root store' % MOZ,
                          cg_moz_hash_index[x]['cert_fingerprint_sha256'],
                          cg_moz_hash_index[x]['cert_der_sha256_b64'])
                missing.append(moz_certs[x])

    if missing:
        r += 1
        print('%d %s intermediates missing from %s' % (
            len(missing), MOZ, title))
        if args.debug > 1:
            print(pprint.pformat(missing), file=sys.stderr)

        moz_missing = await mozilla_missing(missing)
        for sha256, item in moz_missing.items():
            lst = []

            onecrl_match, msg = onecrl_check(sha256, onecrl)
            if onecrl_match:
                lst.append(msg)

            if sha256 in cg_certs:
                cert_type, _ = cg_certs[sha256]
                lst.append('in %s as %s' % (title, cert_type))

                if cert_type == 'intermediate':
                    root_sha256 = root_ancestor(cg_tree, sha256)
                    root_ok, msg = mozilla_root_check(root_sha256, trust)
                    if not root_ok:
                        lst.append(msg)

            if not onecrl_match and sha256 not in cg_certs:
                if sha256 not in ccadb_certs:
                    lst.append('not in CCADB')
                else:
                    lst.append('in CCADB')

                    revoked_rows = []
                    invalid_rows = []
                    no_parent_rows = []
                    root_with_parent_rows = []
                    missing_server_auth_rows = []

                    rows = ccadb_certs[sha256]

                    for row in rows:
                        ret, err = revoked(row)
                        if ret:
                            revoked_rows.append((row, err))
                            continue

                        ret, err = valid_from_to(row)
                        if not ret:
                            invalid_rows.append((row, err))
                            continue

                        cert_type = row['Certificate Record Type']
                        parent_sha256 = row['Parent SHA-256 Fingerprint']

                        if cert_type == 'Root Certificate' and parent_sha256:
                            root_with_parent_rows.append(row)
                            continue

                        if cert_type == 'Intermediate Certificate':
                            if not parent_sha256:
                                no_parent_rows.append(row)
                                continue
                            else:
                                trust_bits = derived_trust_bits(row)
                                if TrustBits.SERVER_AUTHENTICATION not in trust_bits:
                                    missing_server_auth_rows.append((row, trust_bits))

                    if revoked_rows:
                        if len(revoked_rows) == len(rows):
                            lst.append('revoked "%s"' % revoked_rows[0][1])
                        else:
                            lst.append('revoked %d/%d records' % (
                                len(revoked_rows), len(rows)))

                    if invalid_rows:
                        if len(invalid_rows) == len(rows):
                            lst.append('invalid "%s"' % invalid_rows[0][1])
                        else:
                            lst.append('invalid %d/%d records' % (
                                len(invalid_rows), len(rows)))

                    if no_parent_rows:
                        if len(no_parent_rows) == len(rows):
                            lst.append('intermediate with no parent')
                        else:
                            lst.append('intermediate with no parent %d/%d records' % (
                                len(no_parent_rows), len(rows)))

                    if root_with_parent_rows:
                        if len(root_with_parent_rows) == len(rows):
                            lst.append('root with parent')
                        else:
                            lst.append('root with parent %d/%d records' % (
                                len(root_with_parent_rows), len(rows)))

                    if missing_server_auth_rows:
                        if len(missing_server_auth_rows) == len(rows):
                            lst.append(
                                'derived trust bits %s do not include Server Authentication' %
                                missing_server_auth_rows[0][1])
                        else:
                            lst.append(
                                'missing Server Authentication derived trust bit '
                                'in %d/%d records' %
                                (len(missing_server_auth_rows), len(rows)))

                    if len(rows) > 1:
                        duplicates = [
                            '%s %s' % (
                                row['Certificate Record Type'],
                                row['Salesforce Record ID'])
                            for row in rows
                        ]
                        lst.append('duplicate records [%s]' % ', '.join(duplicates))

            msg = sha256
            msg += ' ' + ' '.join(lst) if lst else ''
            print(msg)

    missing = []
    for x in cg_moz_certs_info:
        if (x['cert_type'] == 'intermediate' and
           x['cert_der_sha256_b64'] not in moz_certs):
            missing.append(x)

    if missing:
        r += 1
        print('%d %s intermediates missing from %s' % (
            len(missing), title, MOZ))
        if args.debug > 1:
            print(pprint.pformat(missing), file=sys.stderr)

    return r


async def mozilla_missing(missing) -> dict[str, MozillaIntermediate]:
    CDN_BASE = 'https://firefox-settings-attachments.cdn.mozilla.net/'
    timeout = aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT)

    moz_missing: dict[str, MozillaIntermediate] = {}

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for x in missing:
            der_hash = x['derHash']

            attachment = x['attachment']
            if attachment['mimetype'] != 'application/x-pem-file':
                print('Unsupported mimetype:', x, file=sys.stderr)
                continue

            url = CDN_BASE + attachment['location']
            ok, content_or_err = await download_url(
                session=session,
                url=url,
                label=der_hash)

            if not ok:
                print(content_or_err, file=sys.stderr)
                continue

            pem_cert = content_or_err
            if attachment['size'] != len(pem_cert):
                print('PEM size mismatch: %s' % x, file=sys.stderr)
                continue

            pem_hash = hashlib.sha256(pem_cert).hexdigest()
            if attachment['hash'] != pem_hash:
                print('PEM hash mismatch: %s' % x, file=sys.stderr)
                continue

            cert = load_pem_cert(pem_cert)
            if cert is None:
                continue

            sha256 = fingerprint_sha256(cert)
            if args.debug:
                print('downloaded', sha256, der_hash)

            cert_der_hash = der_sha256_b64(cert)
            if cert_der_hash != der_hash:
                print('DER hash mismatch: %s != %s' % (
                    cert_der_hash, der_hash), file=sys.stderr)
                continue

            moz_missing[sha256] = MozillaIntermediate(
                record=x,
                cert=cert,
                sha256=sha256)

        return moz_missing


def onecrl_check(sha256, onecrl):
    lst = []
    r = onecrl.get(sha256=sha256)
    if r is not None:
        s = 'in OneCRL "%s"' % (
            r['Revocation Status'])
        if r['Comments']:
            s += ' "%s"' % (
                r['Comments'].replace('\r\n', ' '))
        lst.append(s)

        msg = ' '.join(lst) if lst else ''

        return True, msg

    return False, None


def root_ancestor(tree: Tree, sha256: str) -> str:
    node = tree.get_node(sha256)
    if node is None:
        raise ValueError('certificate not in tree: %s' % sha256)

    while True:
        parent = tree.parent(node.identifier)
        if parent is None:
            raise ValueError('certificate has no root ancestor: %s' % sha256)

        if parent.identifier == tree.root:
            return node.identifier

        node = parent


def mozilla_root_check(sha256, trust):
    r = trust.get(sha256=sha256)
    if r is None:
        return False, 'root %s not in CCADB root trust settings' % sha256

    status = r['Mozilla Status']
    if status != 'Included':
        return False, 'root %s %s status "%s"' % (
            sha256, MOZ, status)

    trust_bits = trust.mozilla_trust_bits(sha256=sha256)

    if TrustBits.SERVER_AUTHENTICATION not in trust_bits:
        return False, (
            'root %s not trusted by %s for Server Authentication; trust bits %s' %
            (sha256, MOZ, trust_bits))

    return True, None


async def resolve_inputs(
        args: argparse.Namespace,
        specs: list[InputSpec]
) -> Tuple[dict[str, Union[str, bytes]], int]:
    outputs: dict[str, Union[str, bytes]] = {}
    errors = 0

    timeout = aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT)
    tasks = []

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for spec in specs:
            if spec.path is not None:
                tasks.append(read_file(path=spec.path, label=spec.label))
            else:
                tasks.append(download_url(session=session,
                                          url=spec.url,
                                          label=spec.label))
        results = await asyncio.gather(*tasks)

        for spec, (ok, content_or_err) in zip(specs, results):
            if not ok:
                errors += 1
                print(content_or_err, file=sys.stderr)
                continue

            outputs[spec.dest] = content_or_err

            if args.verbose:
                src = str(spec.path) if spec.path is not None else spec.url
                print(f'{spec.label}: {len(content_or_err)} bytes from {src}')

    return outputs, errors


async def download_url(
        *,
        session: aiohttp.ClientSession,
        url: str,
        label: str
) -> Tuple[bool, Union[str, bytes]]:
    try:
        async with session.get(url) as response:
            if response.status != 200:
                return False, f'{label}: Error: status code {response.status}'

            content = await response.read()
            return True, content

    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        msg = str(e) or type(e).__name__
        return False, f'{label}: Request failed: {msg}'
    except Exception as e:
        msg = str(e)
        detail = f': {msg}' if msg else ''
        return False, f'{label}: Unexpected {type(e).__name__}{detail}'


async def read_file(
        *,
        path: Path,
        label: str
) -> Tuple[bool, Union[str, bytes]]:
    try:
        return True, path.read_bytes()
    except OSError as e:
        return False, f'{label}: {path.name}: {e}'


def load_pem_cert(data: bytes) -> Optional[x509.Certificate]:
    try:
        cert = x509.load_pem_x509_certificate(data)
        return cert

    except Exception as e:
        # Future-proof: cryptography may raise instead of warn
        pem_sha256 = hashlib.sha256(data).hexdigest().upper()
        print(f'[cert PEM SHA256={pem_sha256}] {type(e).__name__}: {e}',
              file=sys.stderr)


# openssl x509 -in cert.pem -fingerprint -sha256 -noout
# openssl x509 -in cert.pem -outform der | openssl dgst -sha256
def fingerprint_sha256(cert: x509.Certificate) -> str:
    sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
    return sha256


# Mozilla intermediate records JSON "derHash" field.  base64 encoded
# SHA-256 digest vs. hexdigest (openssl x509 -fingerprint).
#
# openssl x509 -in cert.pem -outform der |
#   openssl dgst -sha256 -binary |
#   openssl base64
def der_sha256_b64(cert: x509.Certificate) -> str:
    der_data = cert.public_bytes(encoding=serialization.Encoding.DER)
    sha256_hash = hashlib.sha256(der_data).digest()
    return base64.b64encode(sha256_hash).decode('ascii')


def specs_from_parser(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    url_by_dest: dict[str, str]
) -> list[InputSpec]:
    specs: list[InputSpec] = []

    for dest, url in url_by_dest.items():
        label = help_label_for_dest(parser, dest)
        if label is not None:
            path = getattr(args, dest, None)
            specs.append(InputSpec(dest=dest, label=label, url=url, path=path))

    return specs


def help_label_for_dest(
        parser: argparse.ArgumentParser, dest: str
) -> str:
    # parser._actions is "internal", but stable in practice and widely used.
    for action in parser._actions:
        if action.dest == dest:
            h = action.help
            if h is None or h is argparse.SUPPRESS:
                return
            return h.removesuffix(' path')

    raise KeyError(f'dest not in parser: {dest!r}')


def parse_args():
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='%s and %s certificate analysis' % (title, MOZ))
    parser.add_argument('--certs',
                        metavar='PATH',
                        type=Path,
                        help='certificate archive path')
    parser.add_argument('--tree',
                        metavar='PATH',
                        type=Path,
                        help='JSON certificate tree path')
    parser.add_argument('--moz-int',
                        metavar='PATH',
                        type=Path,
                        help='Mozilla intermediate records JSON path')
    parser.add_argument('-T', '--trust-settings',
                        metavar='PATH',
                        type=Path,
                        help='CCADB root certificate trust bit settings'
                        ' CSV path')
    parser.add_argument('-o', '--onecrl',
                        metavar='PATH',
                        type=Path,
                        help='Mozilla OneCRL CSV path')
    parser.add_argument('-c', '--ccadb',
                        metavar='PATH',
                        type=Path,
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

    URL_BY_DEST = {
        'certs':
        'https://raw.githubusercontent.com/PaloAltoNetworks/'
        'pan-chainguard-content/refs/heads/main/latest-certs/'
        'certificates-new.tgz',
        'tree':
        'https://raw.githubusercontent.com/PaloAltoNetworks/'
        'pan-chainguard-content/refs/heads/main/latest-certs/'
        'certificate-tree.json',
        'moz_int':
        'https://firefox.settings.services.mozilla.com/'
        'v1/buckets/security-state/collections/'
        'intermediates/records',
        'trust_settings':
        'https://ccadb.my.salesforce-sites.com/ccadb/'
        'AllIncludedRootCertsCSV',
        'onecrl':
        'https://ccadb.my.salesforce-sites.com/mozilla/'
        'IntermediateCertsInOneCRLReportCSV',
        'ccadb':
        'https://ccadb.my.salesforce-sites.com/ccadb/'
        'AllCertificateRecordsCSVFormatV5',
    }

    args = parser.parse_args()
    specs = specs_from_parser(parser, args, URL_BY_DEST)

    if args.debug:
        print(args, file=sys.stderr)
        print(specs, file=sys.stderr)

    return args, specs


if __name__ == '__main__':
    main()
