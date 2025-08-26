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

# https://www.ccadb.org/resources
#
# All Certificate Information (root and intermediate) in CCADB (CSV)
# utility functions.
# https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2
#
# All Included Root Certificate Trust Bit Settings:
# https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV

import csv
from datetime import datetime, timezone
from enum import Flag, auto
import sys
from typing import Tuple, Union, Optional


class CcadbError(Exception):
    pass


_FMT = '%Y.%m.%d %z'

__all__ = [
    'valid_from', 'valid_to', 'valid_from_to', 'revoked',
    'TrustBits', 'trust_bits_flag',
    'derived_trust_bits_list', 'derived_trust_bits',
    'root_trust_bits_list', 'root_trust_bits',
    'RootStatusBits', 'root_status_bits_flag', 'root_status_bits',
]


class TrustBits(Flag):
    NONE = 0
    OTHER = auto()
    CLIENT_AUTHENTICATION = auto()
    CODE_SIGNING = auto()
    DOCUMENT_SIGNING = auto()
    OCSP_SIGNING = auto()
    SECURE_EMAIL = auto()
    SERVER_AUTHENTICATION = auto()
    TIME_STAMPING = auto()


TrustBitsMap = {
    'Client Authentication': TrustBits.CLIENT_AUTHENTICATION,
    'Code Signing': TrustBits.CODE_SIGNING,
    'Document Signing': TrustBits.DOCUMENT_SIGNING,
    'OCSP Signing': TrustBits.OCSP_SIGNING,
    'Secure Email': TrustBits.SECURE_EMAIL,
    'Server Authentication': TrustBits.SERVER_AUTHENTICATION,
    'Time Stamping': TrustBits.TIME_STAMPING,
}

TrustBitsMap2 = {v.name: v for v in TrustBitsMap.values()}


class RootStatusBits(Flag):
    NONE = 0
    MOZILLA = auto()
    CHROME = auto()
    APPLE = auto()
    MICROSOFT = auto()


RootStatusBitsMap = {
    'Mozilla Status': RootStatusBits.MOZILLA,
    'Apple Status': RootStatusBits.APPLE,
    'Chrome Status': RootStatusBits.CHROME,
    'Microsoft Status': RootStatusBits.MICROSOFT,
}


def _now():
    now = datetime.now(timezone.utc)

    return now


# CCADB Valid From/To fields are the date only in YYYY.MM.DD format.
# When converted to a date with time, the time used is midnight; for
# example:
#   2024.10.27 -> 2024-10-27 00:00:00+00:00

def valid_from(row: dict[str, str]) -> Tuple[bool, Union[str, None]]:
    k = 'Valid From (GMT)'
    valid_from = datetime.strptime(row[k] + ' +0000', _FMT)
    if _now() < valid_from:
        x = 'Not yet valid (valid from %s)' % row[k]
        return False, x

    return True, None


def valid_to(row: dict[str, str]) -> Tuple[bool, Union[str, None]]:
    k = 'Valid To (GMT)'
    valid_to = datetime.strptime(row[k] + ' +0000', _FMT)
    if valid_to < _now():
        x = 'Expired (valid to %s)' % row[k]
        return False, x

    return True, None


def valid_from_to(row: dict[str, str]) -> Tuple[bool, Union[str, None]]:
    return valid_from(row) and valid_to(row)


def revoked(row: dict[str, str]) -> Tuple[bool, Union[str, None]]:
    k = 'Revocation Status'
    if row[k] not in ['', 'Not Revoked']:
        return True, row[k]

    return False, None


def _trust_bits_list(key: str, row: dict[str, str]) -> list[str]:
    x = row[key]
    if not x:
        return []

    return x.split(';')


def derived_trust_bits_list(row: dict[str, str]) -> list[str]:
    type_ = 'Intermediate Certificate'
    x = row['Certificate Record Type']
    if x != type_:
        raise ValueError('certificate type "%s" not "%s"' % (x, type_))

    key = 'Derived Trust Bits'
    return _trust_bits_list(key, row)


def root_trust_bits_list(row: dict[str, str]) -> list[str]:
    type_ = 'Root Certificate'
    x = row['Certificate Record Type']
    if x != type_:
        raise ValueError('certificate type "%s" not "%s"' % (x, type_))

    key = 'Trust Bits for Root Cert'
    return _trust_bits_list(key, row)


def trust_bits_flag(values: list[str]) -> TrustBits:
    bits = TrustBits.NONE
    for x in values:
        if x in TrustBitsMap:
            bits = bits | TrustBitsMap[x]
        else:
            bits = bits | TrustBits.OTHER

    return bits


def derived_trust_bits(row: dict[str, str]) -> TrustBits:
    x = derived_trust_bits_list(row)
    return trust_bits_flag(x)


def root_trust_bits(row: dict[str, str]) -> TrustBits:
    x = root_trust_bits_list(row)
    return trust_bits_flag(x)


def root_status_bits_flag(row: dict[str, str]) -> RootStatusBits:
    type_ = 'Root Certificate'
    x = row['Certificate Record Type']
    if x != type_:
        raise ValueError('certificate type "%s" not "%s"' % (x, type_))

    bits = RootStatusBits.NONE
    for x in RootStatusBitsMap:
        if x in row and row[x] == 'Included':
            bits = bits | RootStatusBitsMap[x]

    return bits


map_ = {
    ('mozilla', 'Mz'): RootStatusBits.MOZILLA,
    ('apple', 'Ap'): RootStatusBits.APPLE,
    ('chrome', 'Ch'): RootStatusBits.CHROME,
    ('microsoft', 'Ms'): RootStatusBits.MICROSOFT,
}


def root_status_bits(bits: RootStatusBits,
                     compact: bool = False) -> Union[str, list]:
    r = []

    for k, v in map_.items():
        if v in bits:
            r.append(k[1] if compact else k[0])

    return ''.join(r) if compact else r


class CcadbRootTrustSettings:
    def __init__(self, *,
                 path: str,
                 debug: bool = False):
        self._certs = {}
        self._debug = debug

        try:
            with open(path, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile,
                                        dialect='unix')
                for row in reader:
                    sha256 = row['SHA-256 Fingerprint']
                    if self._debug and sha256 in self.certs:
                        print('Duplicate in CCADB Root Trust Settings %s' % (
                            sha256), file=sys.stderr)
                    self._certs[sha256] = row

        except OSError as e:
            raise CcadbError(str(e))

    @property
    def certs(self):
        return self._certs

    def get(self, *, sha256: str) -> Optional[dict[str, str]]:
        if sha256 not in self._certs:
            return

        return self._certs[sha256]

    def root_status_bits_flag(self, *, sha256: str) -> Optional[
            RootStatusBits]:
        if sha256 not in self._certs:
            return
        row = self._certs[sha256]

        bits_map = RootStatusBitsMap.copy()
        del bits_map['Chrome Status']
        bits_map['Google Chrome Status'] = RootStatusBits.CHROME

        bits = RootStatusBits.NONE
        for x in bits_map:
            if x in row and row[x] == 'Included':
                bits = bits | bits_map[x]

        return bits

    # There is no 'Google Chrome Trust Bits'.
    # The Chrome Root Store only trusts Server Authentication.
    def chrome_trust_bits_list(self, *, sha256: str) -> Optional[list]:
        if sha256 not in self._certs:
            return

        bits = self.root_status_bits_flag(sha256=sha256)
        if RootStatusBits.CHROME not in bits:
            return []

        return ['Server Authentication']

    def chrome_trust_bits(self, *, sha256: str) -> Optional[TrustBits]:
        values = self.chrome_trust_bits_list(sha256=sha256)
        if values is None:
            return

        if not values:
            return TrustBits.NONE

        return TrustBits.SERVER_AUTHENTICATION

    def mozilla_trust_bits_list(self, *, sha256: str) -> Optional[list]:
        if sha256 not in self._certs:
            return

        return _trust_bits_list('Mozilla Trust Bits', self._certs[sha256])

    def mozilla_trust_bits(self, *, sha256: str) -> Optional[TrustBits]:
        values = self.mozilla_trust_bits_list(sha256=sha256)
        if values is None:
            return

        if self._debug and not values:
            print('Mozilla Trust Bits null %s' % sha256, file=sys.stderr)

        if values == ['All Trust Bits Turned Off']:
            return TrustBits.NONE

        MAP = {
            'Websites': TrustBits.SERVER_AUTHENTICATION,
            'Email': TrustBits.SECURE_EMAIL,
        }

        bits = TrustBits.NONE
        for x in values:
            if x in MAP:
                bits = bits | MAP[x]
            else:
                bits = bits | TrustBits.OTHER

        if self._debug and TrustBits.OTHER in bits:
            print('Mozilla Trust Bits other %s %s' % (
                values, sha256), file=sys.stderr)

        return bits

    def apple_trust_bits_list(self, *, sha256: str) -> Optional[list]:
        if sha256 not in self._certs:
            return

        return _trust_bits_list('Apple Trust Bits', self._certs[sha256])

    def apple_trust_bits(self, *, sha256: str) -> Optional[TrustBits]:
        values = self.apple_trust_bits_list(sha256=sha256)
        if values is None:
            return

        if self._debug and not values:
            print('Apple Trust Bits null %s' % sha256, file=sys.stderr)

        MAP = {
            'serverAuth': TrustBits.SERVER_AUTHENTICATION,
            'clientAuth': TrustBits.CLIENT_AUTHENTICATION,
            'emailProtection': TrustBits.SECURE_EMAIL,
            'timeStamping': TrustBits.TIME_STAMPING,
            'codeSigning': TrustBits.CODE_SIGNING,
            #  'BrandIndicatorforMessageIdentification': TrustBits.OTHER,
        }

        bits = TrustBits.NONE
        for x in values:
            if x in MAP:
                bits = bits | MAP[x]
            else:
                bits = bits | TrustBits.OTHER

        if self._debug and TrustBits.OTHER in bits:
            print('Apple Trust Bits other %s %s' % (
                values, sha256), file=sys.stderr)

        return bits

    def microsoft_trust_bits_list(self, *, sha256: str) -> Optional[list]:
        if sha256 not in self._certs:
            return

        # DTBs - Derived Trust Bits
        return _trust_bits_list('Microsoft EKUs', self._certs[sha256])

    def microsoft_trust_bits(self, *, sha256: str) -> Optional[TrustBits]:
        values = self.microsoft_trust_bits_list(sha256=sha256)
        if values is None:
            return

        if self._debug and not values:
            print('Microsoft Trust Bits null %s' % sha256, file=sys.stderr)

        bits = trust_bits_flag(values)

        return bits
