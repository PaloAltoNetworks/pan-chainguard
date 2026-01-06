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

# reduce aerodynamic drag

import argparse
import asyncio
import base64
from collections import defaultdict
from contextlib import contextmanager
import contextvars
import hashlib
import os
import sys
from typing import Callable, Optional
import warnings

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    from cryptography.utils import CryptographyDeprecationWarning
except ImportError:
    print('Install cryptography: https://pypi.org/project/cryptography/',
          file=sys.stderr)
    sys.exit(1)

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import title, __version__
import pan_chainguard.util

# for custom showwarning()
_current_cert_id = contextvars.ContextVar('current_cert_id', default=None)
_ORIG_SHOWWARNING = warnings.showwarning

args = None


def main():
    global args
    args = parse_args()

    configure_warnings(args.debug)

    asyncio.run(main_loop())

    sys.exit(0)


async def main_loop():
    if args.certs_new and not pan_chainguard.util.is_writable(args.certs_new):
        print('%s: not writable' % args.certs_new, file=sys.stderr)
        sys.exit(1)

    certs = get_certs(args.certs)

    if args.stats:
        stats(certs)

    if args.show_dups:
        show_dups(certs)

    if args.show:
        show(certs)

    if args.certs_new:
        data = {d['sha256']: (d['type'], d['_content']) for d in certs}
        try:
            pan_chainguard.util.write_cert_archive(
                path=args.certs_new, data=data)
        except pan_chainguard.util.UtilError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)


def get_certs(path):
    try:
        data = pan_chainguard.util.read_cert_archive(
            path=path)
    except pan_chainguard.util.UtilError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    certs = []

    for sha256 in data:
        cert_type, content = data[sha256]
        if args.type and cert_type not in args.type:
            continue

        with warning_cert_context(pem_bytes=content):
            cert = load_pem_cert(content)
            if cert is None:
                continue

        fp = fingerprint_sha256(cert)
        if sha256 != fp:
            print('%s: cert filename does not match content SHA256: %s' % (
                sha256, fp), file=sys.stderr)

        with warning_cert_context(cert_fingerprint=fp):
            common_name_ = common_name(cert.subject)
            if args.verbose and common_name_ is None:
                print('%s: No Common Name' % sha256, file=sys.stderr)

            serial_number = cert.serial_number
            if args.verbose and serial_number <= 0:
                print('%s: Serial Number not positive: %d' % (
                    sha256, serial_number),
                    file=sys.stderr)

            x = {
                'sha256': sha256,
                'type': cert_type,
                '_content': content,
                #  '_cert': cert,
                'pubkey_der_hash_hexdigest': pubkey_der_hash_hexdigest(cert),
                'der_hash_b64': der_hash_b64(cert),
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'signature_hash_algorithm': cert.signature_hash_algorithm.name,
                'subject': cert.subject.rfc4514_string(),
                'common_name': common_name_,
                'issuer': cert.issuer.rfc4514_string(),
                'serial_number': serial_number,
                'not_valid_before': cert.not_valid_before_utc,
                'not_valid_after': cert.not_valid_after_utc,
            }

            x.update(pubkey_info(cert))

            x['subject_key_identifier'] = None
            try:
                ski = cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier).value
                x['subject_key_identifier'] = ski.digest.hex()
            except ValueError as e:
                print('%s: %s: %s' % (type(e).__name__, sha256, e),
                      file=sys.stderr)
            except x509.ExtensionNotFound:
                if args.verbose:
                    print('%s: No Subject Key Identifier' % sha256,
                          file=sys.stderr)

        certs.append(x)

    return certs


def common_name(name: x509.Name) -> Optional[str]:
    attrs = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if attrs:
        return attrs[0].value

    return


def pubkey_info(cert: x509.Certificate) -> dict:
    pubkey = cert.public_key()
    pubkey_name = type(pubkey).__name__

    x = {}
    if isinstance(pubkey, rsa.RSAPublicKey):
        numbers = pubkey.public_numbers()
        x['public_key_algorithm'] = 'RSA'
        x['public_key_length'] = numbers.n.bit_length()
        x['exponent'] = numbers.e

    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        x['public_key_algorithm'] = 'EC'
        x['public_key_length'] = pubkey.curve.key_size
        x['curve_name'] = pubkey.curve.name

    elif isinstance(pubkey, dsa.DSAPublicKey):
        x['public_key_algorithm'] = 'DSA'
        if args.verbose:
            print('%s: Deprecated key algorithm: %s' % (
                fingerprint_sha256(cert), pubkey_name),
                file=sys.stderr)
    else:
        x['public_key_algorithm'] = pubkey_name
        if verbose:
            print('%s: Unknown key algorithm: %s' % (
                fingerprint_sha256(cert), pubkey_name),
                file=sys.stderr)

    return x


def pubkey_duplicates(certs):
    src = defaultdict(list)

    for d in certs:
        src[d['pubkey_der_hash_hexdigest']].append(d)

    dups = {k: lst for k, lst in src.items() if len(lst) > 1}

    return dups


def stats(certs):
    x = defaultdict(int)

    for d in certs:
        x['total_certificates'] += 1
        x[f'total_{d['type']}_certificates'] += 1
        x[f"public_key_algorithm {d['public_key_algorithm']}"] += 1
        x[f"signature_algorithm {d['signature_algorithm']}"] += 1
        if 'exponent' in d:
            x[f"rsa_exponent {d['exponent']}"] += 1
        if 'curve_name' in d:
            x[f"ec_curve {d['curve_name']}"] += 1
        if d['serial_number'] <= 0:
            x['total_serial_number_not_positive'] += 1
        if d['common_name'] is None:
            x['total_no_common_name'] += 1
        if d['subject_key_identifier'] is None:
            x['total_no_subject_key_identifier'] += 1

    dups = pubkey_duplicates(certs)
    x['total_public_key_duplicates'] = len(dups)

    d = {k: v for k, v in sorted(x.items())}
    for k, v in d.items():
        print('%s: %s' % (k, v))


def show_dups(certs):
    dups = pubkey_duplicates(certs)
    for k in dups:
        print(f'pubkey_der_hash_hexdigest={k}')
        for c in dups[k]:
            print(f"    sha256={c['sha256']}")

    if args.verbose:
        dups = [v for lst in dups.values() for v in lst]
        show(dups)


def show(certs):
    if not len(certs):
        return

    width = max(len(k) for d in certs for k in d)

    for i, d in enumerate(certs):
        if i:
            print()
        for k in d:
            if k[0] == '_':
                continue
            name = k
            value = d[k]
            print(f'{name:<{width}} = {value}')


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


# openssl x509 -in cert.pem -pubkey -noout |
#   openssl pkey -pubin -outform DER
def pubkey_der(cert: x509.Certificate) -> bytes:
    pubkey = cert.public_key()
    return pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


# Use for same public key comparison.
#
# Because SKI generation is not standardized to a single mandatory
# method (and may be absent or issuer-chosen), it should not be used
# as a definitive way to detect duplicate public keys; instead compare
# the public key/SPKI directly
#
# openssl x509 -in cert.pem -pubkey -noout |
#   openssl pkey -pubin -outform DER |
#   openssl dgst -sha256
def pubkey_der_hash_hexdigest(cert: x509.Certificate) -> str:
    pubkey = pubkey_der(cert)
    return hashlib.sha256(pubkey).hexdigest()


# Mozilla intermediate records JSON "derHash" field.  base64 encoded
# SHA-256 digest vs. hexdigest (openssl x509 -fingerprint).
#
# openssl x509 -in cert.pem -outform der |
#   openssl dgst -sha256 -binary |
#   openssl base64
def der_hash_b64(cert: x509.Certificate) -> str:
    der_data = cert.public_bytes(encoding=serialization.Encoding.DER)
    sha256_hash = hashlib.sha256(der_data).digest()
    return base64.b64encode(sha256_hash).decode('ascii')


def configure_warnings(debug: int) -> None:
    if debug == 1:
        # maintain default warnings
        return
    if debug == 0:
        warnings.filterwarnings(action='ignore',
                                category=UserWarning)
        warnings.filterwarnings(action='ignore',
                                category=CryptographyDeprecationWarning)
        return

    # debug > 1
    warnings.filterwarnings(action='always',
                            category=UserWarning)
    warnings.filterwarnings(action='always',
                            category=CryptographyDeprecationWarning)

    def showwarning(message, category, filename, lineno, file=None, line=None):
        cert_id = _current_cert_id.get()
        if cert_id:
            message = f'[{cert_id}] {message}'
        _ORIG_SHOWWARNING(message, category, filename, lineno,
                          file=file, line=line)

    warnings.showwarning = showwarning


@contextmanager
def warning_cert_context(
        *,
        cert: Optional[x509.Certificate] = None,
        cert_fingerprint: Optional[str] = None,
        pem_bytes: Optional[bytes] = None,
        fingerprint_sha256: Optional[Callable[[x509.Certificate], str]] = None
):
    if cert_fingerprint is not None:
        cert_id = f'cert DER SHA256={cert_fingerprint}'
    elif cert is not None:
        if fingerprint_sha256 is None:
            raise ValueError(
                'fingerprint_sha256 is required when cert is provided')
        cert_id = f'cert DER SHA256={fingerprint_sha256(cert)}'
    elif pem_bytes is not None:
        cert_id = (f'cert PEM SHA256='
                   f'{hashlib.sha256(pem_bytes).hexdigest().upper()}')
    else:
        cert_id = None

    token = _current_cert_id.set(cert_id)
    try:
        yield
    finally:
        _current_cert_id.reset(token)


def parse_args():
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='manage certificate archive')
    parser.add_argument('--certs',
                        required=True,
                        metavar='PATH',
                        help='certificate archive path')
    parser.add_argument('--certs-new',
                        metavar='PATH',
                        help='new certificate archive path')
    parser.add_argument('-T', '--type',
                        action='append',
                        choices=['root', 'intermediate'],
                        help='include certificate type(s)')
    parser.add_argument('--stats',
                        action='store_true',
                        help='print certificate stats')
    parser.add_argument('--show',
                        action='store_true',
                        help='show certificate details')
    parser.add_argument('--show-dups',
                        action='store_true',
                        help='show certificates with duplicate public key')
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
