from datetime import timedelta
import unittest

from pan_chainguard.ccadb import *
from pan_chainguard.ccadb import _now

FMT = '%Y.%m.%d'
VALID_FROM = 'Valid From (GMT)'
VALID_TO = 'Valid To (GMT)'

now = _now()
today = now.strftime(FMT)
x = now - timedelta(days=1)
yesterday = x.strftime(FMT)
x = now + timedelta(days=1)
tomorrow = x.strftime(FMT)


class CcadbTest(unittest.TestCase):
    def test_01(self):
        x = today
        t = {VALID_FROM: x}
        r, err = valid_from(t)
        self.assertTrue(r, "%s: %s" % (x, err))
        self.assertIsNone(err)

    def test_02(self):
        x = yesterday
        t = {VALID_FROM: x}
        r, err = valid_from(t)
        self.assertTrue(r, "%s: %s" % (x, err))
        self.assertIsNone(err)

    def test_03(self):
        x = tomorrow
        t = {VALID_FROM: x}
        r, err = valid_from(t)
        self.assertFalse(r, "%s: %s" % (x, err))
        self.assertIsNotNone(err)
        self.assertIn('Not yet valid', err)

    def test_04(self):
        x = tomorrow
        t = {VALID_TO: x}
        r, err = valid_to(t)
        self.assertTrue(r, "%s: %s" % (x, err))
        self.assertIsNone(err)

    def test_05(self):
        x = yesterday
        t = {VALID_TO: x}
        r, err = valid_to(t)
        self.assertFalse(r, "%s: %s" % (x, err))
        self.assertIsNotNone(err)
        self.assertIn('Expired', err)

    def test_06(self):
        x = today
        t = {VALID_TO: x}
        r, err = valid_to(t)
        self.assertFalse(r, "%s: %s" % (x, err))
        self.assertIsNotNone(err)
        self.assertIn('Expired', err)

    def test_07(self):
        t = {
            VALID_FROM: yesterday,
            VALID_TO: tomorrow,
        }
        r, err = valid_from_to(t)
        self.assertTrue(r, "%s: %s" % (t, err))
        self.assertIsNone(err)

    def test_08(self):
        t = {
            VALID_FROM: yesterday,
            VALID_TO: today,
        }
        r, err = valid_from_to(t)
        self.assertFalse(r, "%s: %s" % (t, err))
        self.assertIsNotNone(err)
        self.assertIn('Expired', err)
