from pathlib import Path
from typing import Generator
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def root_ca_cert(tmp_path: Path) -> Generator[Path, None, None]:
    # Prevent the charm's _update_tls_certificates method to try and write our local filesystem
    with patch("src.cosl.coordinated_workers.worker.ROOT_CA_CERT", new=tmp_path / "rootcacert"):
        yield tmp_path / "rootcacert"
