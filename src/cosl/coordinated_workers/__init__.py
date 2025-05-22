# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""This module is only here to warn users that the `coordinated_workers` have been moved out of cosl."""

raise ImportError(
    "The `coordinated_workers` module has been removed from `cosl`. "
    "Use `https://github.com/canonical/cos-coordinated-workers` instead."
)
