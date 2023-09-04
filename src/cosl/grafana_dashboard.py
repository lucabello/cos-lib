# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Grafana Dashboard."""

import base64
import json
import logging
import lzma
from typing import Dict, Union

logger = logging.getLogger(__name__)


class GrafanaDashboard(str):
    """GrafanaDashboard represents an actual dashboard in Grafana.

    The class is used to compress and encode, or decompress and decode,
    Grafana Dashboards in JSON format using LZMA.
    """

    @staticmethod
    def _serialize(raw_json: Union[str, bytes]) -> "GrafanaDashboard":
        if not isinstance(raw_json, bytes):
            raw_json = raw_json.encode("utf-8")
        encoded = base64.b64encode(lzma.compress(raw_json)).decode("utf-8")
        return GrafanaDashboard(encoded)

    def _deserialize(self) -> Dict:
        try:
            raw = lzma.decompress(base64.b64decode(self.encode("utf-8"))).decode()
            return json.loads(raw)
        except json.decoder.JSONDecodeError as e:
            logger.error("Invalid Dashboard format: %s", e)
            return {}

    def __repr__(self):
        """Return string representation of self."""
        return "<GrafanaDashboard>"
