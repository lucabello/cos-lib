#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""This module is only here for backwards compatibility.

Its contents have been moved over to cosl.interfaces.cluster and cosl.interfaces.utils.
"""


from cosl.interfaces.utils import DatabagModel, DataValidationError  # noqa # type:ignore
from cosl.interfaces.cluster import *  # noqa # type:ignore

from logging import getLogger

logger = getLogger("interface-deprecated")
logger.warning(
    "this module has been deprecated and may be removed in a future version: "
    "please use cosl.interfaces.cluster and cosl.interfaces.utils instead."
)
