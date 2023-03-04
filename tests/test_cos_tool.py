# Copyright 2020 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
import unittest.mock
from pathlib import PosixPath

from cosl import CosTool


class TestTool(unittest.TestCase):
    """Test that the cos-tool base implementation works."""

    def assert_type_error_helper(self, func, *args, **kwargs):
        with self.assertRaises(TypeError) as cm:
            func(*args, **kwargs)
        self.assertIn("Either a default query", str(cm.exception))

    # pylint: disable=protected-access
    @unittest.mock.patch("platform.machine", lambda: "teakettle")
    def test_disable_on_invalid_arch(self):
        tool = CosTool(default_query_type="logql")
        self.assertIsNone(tool.path)
        self.assertTrue(tool._disabled)

    # pylint: disable=protected-access
    @unittest.mock.patch("platform.machine", lambda: "x86_64")
    def test_gives_path_on_valid_arch(self):
        """When given a valid arch, it should return the binary path."""
        tool = CosTool(default_query_type="promql")
        self.assertIsInstance(tool.path, PosixPath)

    @unittest.mock.patch("platform.machine", lambda: "x86_64")
    def test_setup_transformer(self):
        """When setup it should know the path to the binary."""
        tool = CosTool(default_query_type="promql")

        self.assertIsInstance(tool.path, PosixPath)

        p = str(tool.path)
        self.assertTrue(p.endswith("cos-tool-amd64"))

    @unittest.mock.patch("platform.machine", lambda: "x86_64")
    def test_typeerror_is_raised_if_no_query_is_used(self):
        """If no default query type or querytpye is set, it should raise."""
        tool = CosTool()

        self.assert_type_error_helper(tool.apply_label_matchers, rules={})
        self.assert_type_error_helper(tool.validate_alert_rules, rules={})
        self.assert_type_error_helper(tool.inject_label_matchers, expression="", topology={})

        p = str(tool.path)
        self.assertTrue(p.endswith("cos-tool-amd64"))
