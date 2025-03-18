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

# All Certificate Information (root and intermediate) in CCADB (CSV)
# utility functions.
# https://www.ccadb.org/resources
# https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2

from datetime import datetime, timezone
from enum import Flag, auto
from typing import Tuple, Union

_FMT = '%Y.%m.%d %z'

__all__ = [
    'valid_from', 'valid_to', 'valid_from_to', 'revoked',
    'TrustBits', 'derived_trust_bits_list', 'derived_trust_bits_flag',
    'derived_trust_bits',
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


# https://www.ccadb.org/cas/fields#formula-fields
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


def derived_trust_bits_list(row: dict[str, str]) -> list[str]:
    k = 'Derived Trust Bits'
    derived_trust_bits = row[k]
    if not derived_trust_bits:
        return []

    return derived_trust_bits.split(';')


def derived_trust_bits_flag(values: list[str]) -> TrustBits:
    bits = TrustBits.NONE
    for x in values:
        if x in TrustBitsMap:
            bits = bits | TrustBitsMap[x]
        else:
            bits = bits | TrustBits.OTHER

    return bits


def derived_trust_bits(row: dict[str, str]) -> TrustBits:
    x = derived_trust_bits_list(row)
    return derived_trust_bits_flag(x)


def root_status_bits_flag(row: dict[str, str]) -> RootStatusBits:
    root = 'Root Certificate'
    if row['Certificate Record Type'] != root:
        raise ValueError('certificate type not %s' % root)

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
