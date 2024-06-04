# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
from typing import List
from unittest.mock import _Call, patch

import pytest

from src.cosl.loki_logger import LokiHandler


def _get_loki_http_post_payload(call: _Call):
    """Extract the POSTed json payload from the intercepted LokiLogger calls."""
    return json.loads(call.args[1].decode("utf-8"))


def _get_logs_severity(calls: List[_Call]):
    """Extract the loglevel from the intercepted LokiLogger calls."""
    return [
        _get_loki_http_post_payload(call)["streams"][0]["stream"]["severity"] for call in calls
    ]


def _get_loki_urls(calls: List[_Call]):
    """Extract the loki urls from the intercepted lokilogger calls."""
    return [call.args[0].full_url for call in calls]


@pytest.mark.parametrize("n_lokis", (1, 2, 5))
@pytest.mark.parametrize("loglevel_info", (True, False))
@patch("src.cosl.loki_logger.LokiEmitter._send_request")
def test_root_logging(send_request, n_lokis, loglevel_info):
    root_logger = logging.getLogger()

    urls = []
    created_handlers = []

    for i in range(n_lokis):
        url = f"http://loki_{i}.com"
        urls.append(url)
        handler = LokiHandler(url=url, labels={"test-label": f"loki-id-{i}"})

        root_logger.addHandler(handler)
        created_handlers.append(handler)

    try:
        any_logger = logging.getLogger("test-foo")
        if loglevel_info:
            any_logger.setLevel("INFO")

        any_logger.info("something")
        any_logger.error("something else")
    finally:
        # Cleanup the test env:
        #   We're mutating the root logger by adding handlers to it,
        #   that means any tests that will run after this one will also log to our
        #   handlers unless we do this cleanup.
        for handler in created_handlers:
            root_logger.removeHandler(handler)

    # check the intercepted calls.
    # we expect to see the info call and the error call, for every loki handler.
    # each info log gets sent to each loki handler
    # then each error log gets sent to each loki handler

    assert send_request.call_count == 2 * n_lokis

    assert _get_loki_urls(send_request.call_args_list) == urls * 2

    assert (
        _get_logs_severity(send_request.call_args_list) == ["info"] * n_lokis + ["error"] * n_lokis
    )
