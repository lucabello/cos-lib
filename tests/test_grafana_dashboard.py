# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest

from cosl import GrafanaDashboard


class TestDashboard(unittest.TestCase):
    """Tests the GrafanaDashboard class."""

    def test_serializes_and_deserializes(self):
        expected_output = {"msg": "this is the expected output after passing through the class."}

        dash = GrafanaDashboard._serialize(json.dumps(expected_output))

        assert dash._deserialize() == expected_output
