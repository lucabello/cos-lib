# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
# Original LokiEmitter/LokiHandler implementation from
# https://github.com/GreyZmeem/python-logging-loki (MIT licensed)

"""Loki logger."""

import copy
import functools
import json
import logging
import string
import time
import urllib.error
from logging.config import ConvertingDict
from typing import Any, Dict, Optional, Tuple, cast
from urllib import request

logger = logging.getLogger("loki-logger")

# prevent infinite recursion because on failure urllib3 will push more logs
# https://github.com/GreyZmeem/python-logging-loki/issues/18
logging.getLogger("urllib3").setLevel(logging.INFO)


class LokiEmitter:
    """Base Loki emitter class."""

    #: Success HTTP status code from Loki API.
    success_response_code: int = 204

    #: Label name indicating logging level.
    level_label: str = "severity"
    #: Label name indicating logger name.
    logger_label: str = "logger"

    #: String contains chars that can be used in label names in LogQL.
    label_allowed_chars: str = "".join((string.ascii_letters, string.digits, "_"))
    #: A list of pairs of characters to replace in the label name.
    label_replace_with: Tuple[Tuple[str, str], ...] = (
        ("'", ""),
        ('"', ""),
        (" ", "_"),
        (".", "_"),
        ("-", "_"),
    )

    def __init__(
        self, url: str, labels: Optional[Dict[str, str]] = None, cert: Optional[str] = None
    ):
        """Create new Loki emitter.

        Arguments:
            url: Endpoint used to send log entries to Loki (e.g.
            `https://my-loki-instance/loki/api/v1/push`).
            labels: Default labels added to every log record.
            cert: Absolute path to a ca cert for TLS authentication.

        """
        #: Tags that will be added to all records handled by this handler.
        self.labels: Dict[str, str] = labels or {}
        #: Loki JSON push endpoint (e.g `http://127.0.0.1/loki/api/v1/push`)
        self.url = url
        #: Optional cert for TLS auth
        self.cert = cert
        #: only notify once on push failure, to avoid spamming error logs
        self._error_notified_once = False

    def _send_request(self, req: request.Request, jsondata_encoded: bytes):
        return request.urlopen(req, jsondata_encoded, capath=self.cert)

    def __call__(self, record: logging.LogRecord, line: str):
        """Send log record to Loki."""
        payload = self.build_payload(record, line)
        req = request.Request(self.url, method="POST")
        req.add_header("Content-Type", "application/json; charset=utf-8")
        jsondata_encoded = json.dumps(payload).encode("utf-8")

        try:
            resp = self._send_request(req, jsondata_encoded)
        except urllib.error.HTTPError as e:
            if not self._error_notified_once:
                logger.error(f"error pushing logs to {self.url}: {e.status, e.reason}")  # type: ignore
                self._error_notified_once = True
            return

        if resp.getcode() != self.success_response_code:
            raise ValueError(
                "Unexpected Loki API response status code: {0}".format(resp.status_code)
            )

    def build_payload(self, record: logging.LogRecord, line: str) -> Dict[str, Any]:
        """Build JSON payload with a log entry."""
        labels = self.build_labels(record)
        ns = 1e9
        ts = str(int(time.time() * ns))
        stream = {
            "stream": labels,
            "values": [[ts, line]],
        }
        return {"streams": [stream]}

    @functools.lru_cache(256)
    def format_label(self, label: str) -> str:
        """Build label to match prometheus format.

        `Label format <https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels>`_
        """
        for char_from, char_to in self.label_replace_with:
            label = label.replace(char_from, char_to)
        return "".join(char for char in label if char in self.label_allowed_chars)

    def build_labels(self, record: logging.LogRecord) -> Dict[str, str]:
        """Return labels that must be sent to Loki with a log record."""
        labels: Dict[str, str] = (
            dict(self.labels) if isinstance(self.labels, ConvertingDict) else self.labels
        )
        labels = cast(Dict[str, Any], copy.deepcopy(labels))
        labels[self.level_label] = record.levelname.lower()
        labels[self.logger_label] = record.name

        extra_labels = getattr(record, "labels", {})
        if not isinstance(extra_labels, dict):
            return labels

        for label_name, label_value in extra_labels.items():
            cleared_name = self.format_label(label_name)
            if cleared_name:
                labels[cleared_name] = label_value

        return labels


class LokiHandler(logging.Handler):
    """Log handler that sends log records to Loki.

    `Loki API <https://github.com/grafana/loki/blob/master/docs/api.md>`  # wokeignore:rule=master
    """

    def __init__(
        self,
        url: str,
        labels: Optional[Dict[str, str]] = None,
        # username, password tuple
        cert: Optional[str] = None,
    ):
        """Create new Loki logging handler.

        Arguments:
            url: Endpoint used to send log entries to Loki (e.g.
            `https://my-loki-instance/loki/api/v1/push`).
            labels: Default labels added to every log record.
            cert: Optional absolute path to cert file for TLS auth.

        """
        super().__init__()
        self.emitter = LokiEmitter(url, labels, cert)

    def emit(self, record: logging.LogRecord):
        """Send log record to Loki."""
        # noinspection PyBroadException
        try:
            self.emitter(record, self.format(record))
        except Exception:
            self.handleError(record)
