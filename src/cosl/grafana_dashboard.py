# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Grafana Dashboard."""

import base64
import binascii
import hashlib
import json
import logging
import lzma
import warnings
from typing import Any, ClassVar, Dict, Tuple, Union

logger = logging.getLogger(__name__)


class GrafanaDashboard(str):
    """GrafanaDashboard represents an actual dashboard in Grafana.

    The class is used to compress and encode, or decompress and decode,
    Grafana Dashboards in JSON format using LZMA.
    """

    @staticmethod
    def _serialize(raw_json: Union[str, bytes]) -> "GrafanaDashboard":
        warnings.warn(
            "GrafanaDashboard._serialize is deprecated; use LZMABase64.compress(json.dumps(...)) instead.",
            category=DeprecationWarning,
        )
        return GrafanaDashboard(LZMABase64.compress(raw_json))

    def _deserialize(self) -> Dict[str, Any]:
        warnings.warn(
            "GrafanaDashboard._deserialize is deprecated; use json.loads(LZMABase64.decompress(...)) instead.",
            category=DeprecationWarning,
        )
        try:
            return json.loads(LZMABase64.decompress(self))
        except json.decoder.JSONDecodeError as e:
            logger.error("Invalid Dashboard format: %s", e)
            return {}

    def __repr__(self):
        """Return string representation of self."""
        return "<GrafanaDashboard>"


class LZMABase64:
    """A helper class for LZMA-compressed-base64-encoded strings.

    This is useful for transferring over juju relation data, which can only have keys of type string.
    """

    @classmethod
    def compress(cls, raw_json: Union[str, bytes]) -> str:
        """LZMA-compress and base64-encode into a string."""
        if not isinstance(raw_json, bytes):
            raw_json = raw_json.encode("utf-8")
        return base64.b64encode(lzma.compress(raw_json)).decode("utf-8")

    @classmethod
    def decompress(cls, compressed: str) -> str:
        """Decompress from base64-encoded-lzma-compressed string."""
        return lzma.decompress(base64.b64decode(compressed.encode("utf-8"))).decode()


class DashboardPath40UID:
    """A helper class for dashboard UID of length 40, generated from charm name and dashboard path."""

    length: ClassVar[int] = 40

    @classmethod
    def _hash(cls, components: Tuple[str, ...], length: int) -> str:
        return hashlib.shake_256("-".join(components).encode("utf-8")).hexdigest(length)

    @classmethod
    def generate(cls, charm_name: str, dashboard_path: str) -> str:
        """Generate a dashboard uid from charm name and dashboard path.

        The combination of charm name and dashboard path (relative to the charm root) is guaranteed to be unique across
        the ecosystem. By design, this intentionally does not take into account instances of the same charm with
        different charm revisions, which could have different dashboard versions.
        Ref: https://github.com/canonical/observability/pull/206

        The max length grafana allows for a dashboard uid is 40.
        Ref: https://grafana.com/docs/grafana/latest/developers/http_api/dashboard/#identifier-id-vs-unique-identifier-uid

        Args:
            charm_name: The name of the charm (not app!) that owns the dashboard.
            dashboard_path: Path (relative to charm root) to the dashboard file.

        Returns: A uid based on the input args.
        """
        # Since the digest is bytes, we need to convert it to a charset that grafana accepts.
        # Let's use hexdigest, which means 2 chars per byte, reducing our effective digest size to 20.
        return cls._hash((charm_name, dashboard_path), cls.length // 2)

    @classmethod
    def is_valid(cls, uid: str) -> bool:
        """Check if the given UID is a valid "Path-40" UID.

        The UID must be of a particular length, and since we generate it with hexdigest() then we also know it must
        unhexlify.

        This is not a bullet-proof check, because it's plausible that some dashboard would have a 40-length hexstring as
        its uid, but given the current state of the ecosystem, it's quite unlikely.
        """
        if not uid:
            return False
        if len(uid) != cls.length:
            return False
        try:
            binascii.unhexlify(uid)
        except binascii.Error:
            return False
        return True
