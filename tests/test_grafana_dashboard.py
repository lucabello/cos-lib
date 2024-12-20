# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest

from cosl import DashboardPath40UID, GrafanaDashboard, LZMABase64


class TestRoundTripEncDec(unittest.TestCase):
    """Tests the round-trip encoding/decoding of the GrafanaDashboard class."""

    def test_round_trip(self):
        d = {
            "some": "dict",
            "with": "keys",
            "even": [{"nested": "types", "and_integers": [42, 42]}],
        }
        self.assertDictEqual(d, GrafanaDashboard._serialize(json.dumps(d))._deserialize())


class TestLZMABase64(unittest.TestCase):
    """Tests the round-trip encoding/decoding of the GrafanaDashboard class."""

    def test_round_trip(self):
        s = "starting point"
        self.assertEqual(s, LZMABase64.decompress(LZMABase64.compress(s)))


class TestGenerateUID(unittest.TestCase):
    """Spec for the UID generation logic."""

    def test_uid_length_is_40(self):
        self.assertEqual(40, len(DashboardPath40UID.generate("my-charm", "my-dash.json")))

    def test_collisions(self):
        """A very naive and primitive collision check that is meant to catch trivial errors."""
        self.assertNotEqual(
            DashboardPath40UID.generate("some-charm", "dashboard1.json"),
            DashboardPath40UID.generate("some-charm", "dashboard2.json"),
        )

        self.assertNotEqual(
            DashboardPath40UID.generate("some-charm", "dashboard.json"),
            DashboardPath40UID.generate("diff-charm", "dashboard.json"),
        )

    def test_validity(self):
        """Make sure validity check fails for trivial cases."""
        self.assertFalse(DashboardPath40UID.is_valid("1234"))
        self.assertFalse(DashboardPath40UID.is_valid("short non-hex string"))
        self.assertFalse(DashboardPath40UID.is_valid("non-hex string, crafted to be 40 chars!!"))

        self.assertTrue(DashboardPath40UID.is_valid("0" * 40))
        self.assertTrue(
            DashboardPath40UID.is_valid(
                DashboardPath40UID.generate("some-charm", "dashboard.json")
            )
        )
