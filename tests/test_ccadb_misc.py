import unittest

from pan_chainguard.ccadb import *
from pan_chainguard.ccadb import TrustBitsMap

REVOCATION_STATUS = 'Revocation Status'
DERIVED_TRUST_BITS = 'Derived Trust Bits'  # Intermediate Certificate
ROOT_TRUST_BITS = 'Trust Bits for Root Cert'  # Root Certificate
TRUST_BITS = {
    DERIVED_TRUST_BITS: {
        '': derived_trust_bits,
        'list': derived_trust_bits_list,
        'flag': trust_bits_flag,
        'type': 'Intermediate Certificate',
    },
    ROOT_TRUST_BITS: {
        '': root_trust_bits,
        'list': root_trust_bits_list,
        'flag': trust_bits_flag,
        'type': 'Root Certificate',
    },
}


class CcadbTest(unittest.TestCase):
    def test_01(self):
        x = ''
        t = {REVOCATION_STATUS: x}
        r, err = revoked(t)
        self.assertFalse(r, "%s: %s" % (x, err))
        self.assertIsNone(err)

    def test_02(self):
        x = 'Not Revoked'
        t = {REVOCATION_STATUS: x}
        r, err = revoked(t)
        self.assertFalse(r, "%s: %s" % (x, err))
        self.assertIsNone(err)

    def test_03(self):
        x = 'Revoked'
        t = {REVOCATION_STATUS: x}
        r, err = revoked(t)
        self.assertTrue(r, "%s: %s" % (x, err))
        self.assertIsNotNone(err)
        self.assertEqual('Revoked', err)

    def test_04(self):
        x = 'Unknown'
        t = {REVOCATION_STATUS: x}
        r, err = revoked(t)
        self.assertTrue(r, "%s: %s" % (x, err))
        self.assertIsNotNone(err)
        self.assertEqual('Unknown', err)

    def test_05(self):
        for k in TRUST_BITS:
            x = ''
            t = {
                'Certificate Record Type': TRUST_BITS[k]['type'],
                k: x,
            }

            r = TRUST_BITS[k]['list'](t)
            self.assertListEqual([], r)

            bits = TRUST_BITS[k]['flag'](r)
            self.assertEqual(TrustBits.NONE, bits)

            bits = TRUST_BITS[k][''](t)
            self.assertEqual(TrustBits.NONE, bits)

    def test_06(self):
        for k in TRUST_BITS:
            x = 'abcd'
            t = {
                'Certificate Record Type': TRUST_BITS[k]['type'],
                k: x,
            }

            r = TRUST_BITS[k]['list'](t)
            self.assertListEqual([x], r)

            bits = TRUST_BITS[k]['flag'](r)
            self.assertEqual(TrustBits.OTHER, bits)

            bits = TRUST_BITS[k][''](t)
            self.assertEqual(TrustBits.OTHER, bits)

    def test_07(self):
        for k in TRUST_BITS:
            x = 'Server Authentication'
            t = {
                'Certificate Record Type': TRUST_BITS[k]['type'],
                k: x,
            }

            r = TRUST_BITS[k]['list'](t)
            self.assertListEqual([x], r)

            bits = TRUST_BITS[k]['flag'](r)
            self.assertEqual(TrustBitsMap[x], bits)

            bits = TRUST_BITS[k][''](t)
            self.assertEqual(TrustBitsMap[x], bits)

    def test_08(self):
        for k in TRUST_BITS:
            x = ';'.join(TrustBitsMap.keys())
            t = {
                'Certificate Record Type': TRUST_BITS[k]['type'],
                k: x,
            }

            r = TRUST_BITS[k]['list'](t)
            self.assertListEqual(list(TrustBitsMap.keys()), r)

            bits = TRUST_BITS[k]['flag'](r)
            for x in TrustBitsMap.values():
                self.assertIn(x, bits)

            bits = TRUST_BITS[k][''](t)
            for x in TrustBitsMap.values():
                self.assertIn(x, bits)

    def test_09(self):
        row = {
            "Certificate Record Type": "Intermediate Certificate",
            "Mozilla Status": "Not Included",
            "Apple Status": "Not Included",
            "Chrome Status": "Not Included",
            "Microsoft Status": "Not Included",
        }
        r = RootStatusBits.NONE

        with self.assertRaises(ValueError) as e:
            bits = root_status_bits_flag(row)
        x = ('certificate type "Intermediate Certificate" '
             'not "Root Certificate"')
        self.assertEqual(str(e.exception), x)

    def test_10(self):
        row = {
            "Certificate Record Type": "Root Certificate",
            "Mozilla Status": "Not Included",
            "Apple Status": "Not Included",
            "Chrome Status": "Not Included",
            "Microsoft Status": "Not Included",
        }
        r = RootStatusBits.NONE

        bits = root_status_bits_flag(row)
        self.assertEqual(bits, r)
        r = root_status_bits(bits)
        self.assertEqual(r, [])

    def test_11(self):
        row = {
            "Certificate Record Type": "Root Certificate",
            "Mozilla Status": "Included",
            "Apple Status": "Included",
            "Chrome Status": "Included",
            "Microsoft Status": "Included",
        }
        r = (RootStatusBits.MOZILLA |
             RootStatusBits.APPLE |
             RootStatusBits.CHROME |
             RootStatusBits.MICROSOFT)

        bits = root_status_bits_flag(row)
        self.assertEqual(bits, r)
        r = root_status_bits(bits)
        self.assertEqual(r, ['mozilla', 'apple', 'chrome', 'microsoft'])
        r = root_status_bits(bits, compact=True)
        self.assertEqual(r, 'MzApChMs')

    def test_12(self):
        row = {
            "Certificate Record Type": "Root Certificate",
            "Mozilla Status": "Included",
            "Apple Status": "Included",
            "Chrome Status": "Not Included",
            "Microsoft Status": "Not Included",
        }
        r = (RootStatusBits.MOZILLA |
             RootStatusBits.APPLE)

        bits = root_status_bits_flag(row)
        self.assertEqual(bits, r)
        r = root_status_bits(bits)
        self.assertEqual(r, ['mozilla', 'apple'])
        r = root_status_bits(bits, compact=True)
        self.assertEqual(r, 'MzAp')
