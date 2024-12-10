#!/usr/bin/env python3
# Copyright 2024 Canonical
# See LICENSE file for licensing details.

"""Shared utilities for the cosl interfaces."""

import json
import logging
from typing import (
    MutableMapping,
    Optional,
)

import pydantic
from pydantic import ConfigDict

log = logging.getLogger("utils")

BUILTIN_JUJU_KEYS = {"ingress-address", "private-address", "egress-subnets"}

# =================
# | Databag Model |
# =================

# Note: MutableMapping is imported from the typing module and not collections.abc
# because subscripting collections.abc.MutableMapping was added in python 3.9, but
# most of our charms are based on 20.04, which has python 3.8.

_RawDatabag = MutableMapping[str, str]


class DataValidationError(Exception):
    """Raised when relation databag validation fails."""


class DatabagModel(pydantic.BaseModel):
    """Base databag model."""

    model_config = ConfigDict(
        # tolerate additional keys in databag
        extra="ignore",
        # Allow instantiating this class by field name (instead of forcing alias).
        populate_by_name=True,
    )  # type: ignore
    """Pydantic config."""

    @classmethod
    def load(cls, databag: _RawDatabag):
        """Load this model from a Juju databag."""
        try:
            data = {
                k: json.loads(v)
                for k, v in databag.items()
                # Don't attempt to parse model-external values
                if k in {(f.alias or n) for n, f in cls.__fields__.items()}  # type: ignore
            }
        except json.JSONDecodeError as e:
            msg = f"invalid databag contents: expecting json. {databag}"
            log.error(msg)
            raise DataValidationError(msg) from e

        try:
            return cls.model_validate_json(json.dumps(data))  # type: ignore
        except pydantic.ValidationError as e:
            msg = f"failed to validate databag: {databag}"
            if databag:
                log.debug(msg, exc_info=True)
            raise DataValidationError(msg) from e

    def dump(self, databag: Optional[_RawDatabag] = None, clear: bool = True) -> _RawDatabag:
        """Write the contents of this model to Juju databag.

        :param databag: the databag to write the data to.
        :param clear: ensure the databag is cleared before writing it.
        """
        _databag: _RawDatabag = {} if databag is None else databag

        if clear:
            _databag.clear()

        dct = self.model_dump(mode="json", by_alias=True, exclude_defaults=True)  # type: ignore
        _databag.update({k: json.dumps(v) for k, v in dct.items()})
        return _databag


# FIXME: in pydantic v2, the json stuff we've been doing is no longer necessary.
#  It becomes much easier to work with Json fields and the databagmodel class becomes much simpler.
#  We should rewrite the cluster implementation to use this class,
#  and replace the original DatabagModel with it
class DatabagModelV2(pydantic.BaseModel):
    """Base databag model."""

    model_config = ConfigDict(
        # tolerate additional keys in databag
        extra="ignore",
        # Allow instantiating this class by field name (instead of forcing alias).
        populate_by_name=True,
    )  # type: ignore
    """Pydantic config."""

    @classmethod
    def load(cls, databag: _RawDatabag):
        """Load this model from a Juju databag."""
        try:
            return cls.model_validate_json(json.dumps(dict(databag)))  # type: ignore
        except pydantic.ValidationError as e:
            msg = f"failed to validate databag: {databag}"
            if databag:
                log.debug(msg, exc_info=True)
            raise DataValidationError(msg) from e

    def dump(self, databag: Optional[_RawDatabag] = None, clear: bool = True) -> _RawDatabag:
        """Write the contents of this model to Juju databag.

        :param databag: the databag to write the data to.
        :param clear: ensure the databag is cleared before writing it.
        """
        _databag: _RawDatabag = {} if databag is None else databag

        if clear:
            _databag.clear()

        dct = self.model_dump(mode="json", by_alias=True, exclude_defaults=True, round_trip=True)  # type: ignore
        _databag.update(dct)
        return _databag
