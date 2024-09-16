from contextlib import ExitStack
from pathlib import Path
from typing import Generator
from unittest.mock import patch

import pytest
import tenacity


@pytest.fixture(autouse=True)
def patch_all():
    with ExitStack() as stack:
        # so we don't have to wait for minutes:
        stack.enter_context(
            patch(
                "cosl.coordinated_workers.worker.Worker.SERVICE_START_RETRY_WAIT",
                new=tenacity.wait_none(),
            )
        )
        stack.enter_context(
            patch(
                "cosl.coordinated_workers.worker.Worker.SERVICE_START_RETRY_STOP",
                new=tenacity.stop_after_delay(1),
            )
        )
        stack.enter_context(
            patch(
                "cosl.coordinated_workers.worker.Worker.SERVICE_STATUS_UP_RETRY_WAIT",
                new=tenacity.wait_none(),
            )
        )
        stack.enter_context(
            patch(
                "cosl.coordinated_workers.worker.Worker.SERVICE_STATUS_UP_RETRY_STOP",
                new=tenacity.stop_after_delay(1),
            )
        )

        stack.enter_context(
            patch("cosl.coordinated_workers.worker.Worker.running_version", new=lambda _: "42.42")
        )

        yield


@pytest.fixture(autouse=True)
def root_ca_cert(tmp_path: Path) -> Generator[Path, None, None]:
    # Prevent the charm's _update_tls_certificates method to try and write our local filesystem
    with patch("src.cosl.coordinated_workers.worker.ROOT_CA_CERT", new=tmp_path / "rootcacert"):
        yield tmp_path / "rootcacert"
