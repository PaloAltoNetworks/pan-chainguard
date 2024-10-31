import unittest

from pan_chainguard.ccadb import *
from pan_chainguard.ccadb import TrustBitsMap

REVOCATION_STATUS = 'Revocation Status'
DERIVED_TRUST_BITS = 'Derived Trust Bits'


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
        x = ''
        t = {DERIVED_TRUST_BITS: x}
        r = derived_trust_bits_list(t)
        self.assertListEqual([], r)

        bits = derived_trust_bits_flag(r)
        self.assertEqual(TrustBits.NONE, bits)

        bits = derived_trust_bits(t)
        self.assertEqual(TrustBits.NONE, bits)

    def test_06(self):
        x = 'abcd'
        t = {DERIVED_TRUST_BITS: x}
        r = derived_trust_bits_list(t)
        self.assertListEqual([x], r)

        bits = derived_trust_bits_flag(r)
        self.assertEqual(TrustBits.OTHER, bits)

        bits = derived_trust_bits(t)
        self.assertEqual(TrustBits.OTHER, bits)

    def test_07(self):
        x = 'Server Authentication'
        t = {DERIVED_TRUST_BITS: x}
        r = derived_trust_bits_list(t)
        self.assertListEqual([x], r)

        bits = derived_trust_bits_flag(r)
        self.assertEqual(TrustBitsMap[x], bits)

        bits = derived_trust_bits(t)
        self.assertEqual(TrustBitsMap[x], bits)

    def test_08(self):
        x = ';'.join(TrustBitsMap.keys())
        t = {DERIVED_TRUST_BITS: x}
        r = derived_trust_bits_list(t)
        self.assertListEqual(list(TrustBitsMap.keys()), r)

        bits = derived_trust_bits_flag(r)
        for x in TrustBitsMap.values():
            self.assertIn(x, bits)

        bits = derived_trust_bits(t)
        for x in TrustBitsMap.values():
            self.assertIn(x, bits)
