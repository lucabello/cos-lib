import logging
import tempfile

import pytest
from ops import CharmBase
from scenario import Container, Context, ExecOutput, Mount, State

from src.cosl.coordinated_workers.nginx import (
    CA_CERT_PATH,
    CERT_PATH,
    KEY_PATH,
    NGINX_CONFIG,
    Nginx,
)

logger = logging.getLogger(__name__)


@pytest.fixture
def certificate_mounts():
    temp_files = {}
    for path in {KEY_PATH, CERT_PATH, CA_CERT_PATH}:
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_files[path] = temp_file

    mounts = {}
    for cert_path, temp_file in temp_files.items():
        mounts[cert_path] = Mount(cert_path, temp_file.name)

    # TODO: Do we need to clean up the temp files since delete=False was set?
    return mounts


@pytest.fixture
def nginx_context():
    return Context(CharmBase, meta={"name": "foo", "containers": {"nginx": {"type": "oci-image"}}})


def test_certs_on_disk(certificate_mounts: dict, nginx_context: Context):
    # GIVEN any charm with a container
    ctx = nginx_context

    # WHEN we process any event
    with ctx.manager(
        "update-status",
        state=State(containers=[Container("nginx", can_connect=True, mounts=certificate_mounts)]),
    ) as mgr:
        charm = mgr.charm
        nginx = Nginx(charm, lambda: "foo_string", None)

        # THEN the certs exist on disk
        assert nginx.are_certificates_on_disk


def test_certs_deleted(certificate_mounts: dict, nginx_context: Context):
    # Test deleting the certificates.

    # GIVEN any charm with a container
    ctx = nginx_context

    # WHEN we process any event
    with ctx.manager(
        "update-status",
        state=State(containers=[Container("nginx", can_connect=True, mounts=certificate_mounts)]),
    ) as mgr:
        charm = mgr.charm
        nginx = Nginx(charm, lambda: "foo_string", None)

        # AND when we call delete_certificates
        nginx.delete_certificates()

        # THEN the certs get deleted from disk
        assert not nginx.are_certificates_on_disk


def test_reload_calls_nginx_binary_successfully(nginx_context: Context):
    # Test that the reload method calls the nginx binary without error.

    # GIVEN any charm with a container
    ctx = nginx_context

    # WHEN we process any event
    with ctx.manager(
        "update-status",
        state=State(
            containers=[
                Container(
                    "nginx",
                    can_connect=True,
                    exec_mock={("nginx", "-s", "reload"): ExecOutput(return_code=0)},
                )
            ]
        ),
    ) as mgr:
        charm = mgr.charm
        nginx = Nginx(charm, lambda: "foo_string", None)

        # AND when we call reload
        # THEN the nginx binary is used rather than container restart
        assert nginx.reload() is None


def test_has_config_changed(nginx_context: Context):
    # Test changing the nginx config and catching the change.

    # GIVEN any charm with a container and a nginx config file
    test_config = tempfile.NamedTemporaryFile(delete=False, mode="w+")
    ctx = nginx_context
    # AND when we write to the config file
    with open(test_config.name, "w") as f:
        f.write("foo")

    # WHEN we process any event
    with ctx.manager(
        "update-status",
        state=State(
            containers=[
                Container(
                    "nginx",
                    can_connect=True,
                    mounts={"config": Mount(NGINX_CONFIG, test_config.name)},
                )
            ]
        ),
    ) as mgr:
        charm = mgr.charm
        nginx = Nginx(charm, lambda: "foo_string", None)

        # AND a unique config is added
        new_config = "bar"

        # THEN the _has_config_changed method correctly determines that foo != bar
        assert nginx._has_config_changed(new_config)
