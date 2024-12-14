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

import csv
from typing import Optional


class MozillaError(Exception):
    pass


# https://wiki.mozilla.org/CA/Intermediate_Certificates
#
# Intermediate CA Certificates:
# https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV
#

# Non-revoked, non-expired Intermediate CA Certificates chaining up
# to roots in Mozilla's program with the Websites trust bit set:
# https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport

class MozillaCaCerts:
    def __init__(self, *,
                 path: str):
        def insert(row):
            self.certs[row[SHA256]] = row[PEM]

        self.certs = {}
        self.name = None

        try:
            with open(path, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile,
                                        dialect='unix')
                row = next(reader)
                if 'SHA256' in row and 'PEM' in row:
                    SHA256 = 'SHA256'
                    PEM = 'PEM'
                    self.name = 'MozillaIntermediateCerts'
                elif ('SHA-256 Fingerprint' in row and
                      'PEM Info' in row):
                    SHA256 = 'SHA-256 Fingerprint'
                    PEM = 'PEM Info'
                    self.name = 'PublicAllIntermediateCerts'
                else:
                    raise MozillaError('Invalid CSV')
                insert(row)

                for row in reader:
                    insert(row)

        except OSError as e:
            raise MozillaError(str(e))

    def get_cert_pem(self, *, sha256: str) -> Optional[str]:
        if sha256 not in self.certs:
            return

        pem = self.certs[sha256]

        # XXX PublicAllIntermediateCertsWithPEMReport.csv has
        # single quotes around the PEM.
        c = "'"
        if pem.startswith(c):
            pem = pem[1:]
        if pem.endswith(c):
            pem = pem[:-1]

        return pem
