# Copyright 2020 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

from cosl import *  # noqa: F403


class TestImport(unittest.TestCase):
    def test_all(self):
        # WHEN `import *` is used (see module-level import)
        # THEN all public symbols become available
        _ = CosTool  # noqa: F405
        _ = JujuTopology  # noqa: F405
