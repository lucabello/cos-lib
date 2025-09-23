# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest

from cosl.time_validation import is_valid_timespec


@pytest.mark.parametrize(
    "given_time,expected_validity",
    [
        ("0", True),
        ("1y", True),
        ("1m", True),
        ("1w", True),
        ("1d", True),
        ("1h", True),
        ("1m", True),
        ("1s", True),
        ("1ms", True),
        ("1sdgs", False),
        ("1w2d", False),
        ("one week", False),
        ("one hour", False),
    ],
)
def test_is_valid_timespec(given_time, expected_validity):
    assert is_valid_timespec(given_time) == expected_validity
