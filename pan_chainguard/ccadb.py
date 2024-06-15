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

from datetime import datetime, timezone
from typing import Tuple, Union

_FMT = '%Y.%m.%d %z'

__all__ = ['valid_from', 'valid_to', 'valid_from_to', 'revoked']

# All Certificate Information (root and intermediate) in CCADB (CSV)
# utility functions.
# https://www.ccadb.org/resources
# https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2


def _now():
    now = datetime.now(timezone.utc)

    return now


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
