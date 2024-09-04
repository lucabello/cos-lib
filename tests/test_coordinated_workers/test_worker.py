import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import ops
import pytest
import tenacity
import yaml
from ops import Framework
from ops.pebble import Layer, ServiceStatus
from scenario import Container, Context, ExecOutput, Mount, Relation, State
from scenario.runtime import UncaughtCharmError

from cosl.coordinated_workers.worker import CONFIG_FILE, Worker


@pytest.fixture(autouse=True)
def patch_running_version():
    with patch("cosl.coordinated_workers.worker.Worker.running_version", new=lambda _: "42.42"):
        yield


class MyCharm(ops.CharmBase):
    layer = Layer("")

    def __init__(self, framework: Framework):
        super().__init__(framework)
        self.worker = Worker(self, "foo", lambda _: self.layer, {"cluster": "cluster"})


def test_no_roles_error():
    # Test that a charm that defines NO 'role-x' config options, when run,
    # raises a WorkerError

    # WHEN you define a charm with no role-x config options
    ctx = Context(
        MyCharm,
        meta={
            "name": "foo",
            "requires": {"cluster": {"interface": "cluster"}},
            "containers": {"foo": {"type": "oci-image"}},
        },
        config={},
    )

    # IF the charm executes any event
    # THEN the charm raises an error
    with pytest.raises(UncaughtCharmError):
        ctx.run("update-status", State(containers=[Container("foo")]))


@pytest.mark.parametrize(
    "roles_active, roles_inactive, expected",
    (
        (
            ["read", "write", "ingester", "all"],
            ["alertmanager"],
            ["read", "write", "ingester", "all"],
        ),
        (["read", "write"], ["alertmanager"], ["read", "write"]),
        (["read"], ["alertmanager", "write", "ingester", "all"], ["read"]),
        ([], ["read", "write", "ingester", "all", "alertmanager"], []),
    ),
)
def test_roles_from_config(roles_active, roles_inactive, expected):
    # Test that a charm that defines any 'role-x' config options, when run,
    # correctly determines which ones are enabled through the Worker

    # WHEN you define a charm with a few role-x config options
    ctx = Context(
        MyCharm,
        meta={
            "name": "foo",
            "requires": {"cluster": {"interface": "cluster"}},
            "containers": {"foo": {"type": "oci-image"}},
        },
        config={
            "options": {
                f"role-{r}": {"type": "boolean", "default": "false"}
                for r in (roles_active + roles_inactive)
            }
        },
    )

    # AND the charm runs with a few of those set to true, the rest to false
    with ctx.manager(
        "update-status",
        State(
            containers=[Container("foo")],
            config={
                **{f"role-{r}": False for r in roles_inactive},
                **{f"role-{r}": True for r in roles_active},
            },
        ),
    ) as mgr:
        # THEN the Worker.roles method correctly returns the list of only those that are set to true
        assert set(mgr.charm.worker.roles) == set(expected)


def test_worker_restarts_if_some_service_not_up(tmp_path):
    # GIVEN a worker with some services
    MyCharm.layer = Layer(
        {
            "services": {
                "foo": {
                    "summary": "foos all the things",
                    "description": "bar",
                    "startup": "enabled",
                    "override": "merge",
                    "command": "ls -la",
                },
                "bar": {
                    "summary": "bars the foos",
                    "description": "bar",
                    "startup": "enabled",
                    "command": "exit 1",
                },
                "baz": {
                    "summary": "bazzes all of the bars",
                    "description": "bar",
                    "startup": "enabled",
                    "command": "echo hi",
                },
            }
        }
    )
    ctx = Context(
        MyCharm,
        meta={
            "name": "foo",
            "requires": {"cluster": {"interface": "cluster"}},
            "containers": {"foo": {"type": "oci-image"}},
        },
        config={"options": {"role-all": {"type": "boolean", "default": True}}},
    )
    # WHEN the charm receives any event and there are no changes to the config or the layer,
    #  but some of the services are down
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("some: yaml")
    container = Container(
        "foo",
        can_connect=True,
        mounts={"local": Mount(CONFIG_FILE, cfg)},
        exec_mock={("update-ca-certificates", "--fresh"): ExecOutput()},
        service_status={
            "foo": ServiceStatus.INACTIVE,
            "bar": ServiceStatus.ACTIVE,
            "baz": ServiceStatus.INACTIVE,
        },
    )
    state_out = ctx.run(container.pebble_ready_event, State(containers=[container]))

    # THEN the charm restarts all the services that are down
    container_out = state_out.get_container("foo")
    service_statuses = container_out.service_status.values()
    assert all(svc is ServiceStatus.ACTIVE for svc in service_statuses), [
        stat.value for stat in service_statuses
    ]


def test_worker_does_not_restart_external_services(tmp_path):
    # GIVEN a worker with some services and a layer with some other services
    MyCharm.layer = Layer(
        {
            "services": {
                "foo": {
                    "summary": "foos all the things",
                    "override": "merge",
                    "description": "bar",
                    "startup": "enabled",
                    "command": "ls -la",
                }
            }
        }
    )
    other_layer = Layer(
        {
            "services": {
                "bar": {
                    "summary": "bars the foos",
                    "description": "bar",
                    "startup": "enabled",
                    "command": "exit 1",
                },
                "baz": {
                    "summary": "bazzes all of the bars",
                    "description": "bar",
                    "startup": "enabled",
                    "command": "echo hi",
                },
            }
        }
    )

    ctx = Context(
        MyCharm,
        meta={
            "name": "foo",
            "requires": {"cluster": {"interface": "cluster"}},
            "containers": {"foo": {"type": "oci-image"}},
        },
        config={"options": {"role-all": {"type": "boolean", "default": True}}},
    )
    # WHEN the charm receives any event and there are no changes to the config or the layer,
    #  but some of the services are down
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("some: yaml")
    container = Container(
        "foo",
        exec_mock={("update-ca-certificates", "--fresh"): ExecOutput()},
        can_connect=True,
        mounts={"local": Mount(CONFIG_FILE, cfg)},
        layers={"foo": MyCharm.layer, "bar": other_layer},
        service_status={
            # layer foo has some inactive
            "foo": ServiceStatus.INACTIVE,
            # layer bar has some inactive
            "bar": ServiceStatus.ACTIVE,
            "baz": ServiceStatus.INACTIVE,
        },
    )
    state_out = ctx.run(container.pebble_ready_event, State(containers=[container]))

    # THEN the charm restarts all the services that are down
    container_out = state_out.get_container("foo")
    assert container_out.service_status == {
        # layer foo service is now active
        "foo": ServiceStatus.ACTIVE,
        # layer bar services is unchanged
        "bar": ServiceStatus.ACTIVE,
        "baz": ServiceStatus.INACTIVE,
    }


def test_worker_raises_if_service_restart_fails_for_too_long(tmp_path):
    # GIVEN a worker with some services
    MyCharm.layer = Layer(
        {
            "services": {
                "foo": {
                    "summary": "foos all the things",
                    "description": "bar",
                    "startup": "enabled",
                    "command": "ls -la",
                },
            }
        }
    )
    ctx = Context(
        MyCharm,
        meta={
            "name": "foo",
            "requires": {"cluster": {"interface": "cluster"}},
            "containers": {"foo": {"type": "oci-image"}},
        },
        config={"options": {"role-all": {"type": "boolean", "default": True}}},
    )
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("some: yaml")
    container = Container(
        "foo",
        can_connect=True,
        mounts={"local": Mount(CONFIG_FILE, cfg)},
        service_status={
            "foo": ServiceStatus.INACTIVE,
        },
    )

    # WHEN service restart fails
    def raise_change_error(*args):
        raise ops.pebble.ChangeError("something", MagicMock())

    with patch("ops.model.Container.restart", new=raise_change_error):
        # THEN the charm errors out
        with pytest.raises(Exception):
            # technically an ops.pebble.ChangeError but the context manager doesn't catch it for some reason

            with ctx.manager(container.pebble_ready_event, State(containers=[container])) as mgr:
                # so we don't have to wait for minutes:
                mgr.charm.worker.SERVICE_START_RETRY_WAIT = tenacity.wait_none()
                mgr.charm.worker.SERVICE_START_RETRY_STOP = tenacity.stop_after_delay(2)


@pytest.mark.parametrize(
    "remote_databag, expected",
    (
        (
            {
                "remote_write_endpoints": json.dumps([{"url": "test-url.com"}]),
                "worker_config": json.dumps("test"),
            },
            [{"url": "test-url.com"}],
        ),
        ({"remote_write_endpoints": json.dumps(None), "worker_config": json.dumps("test")}, []),
        (
            {
                "remote_write_endpoints": json.dumps(
                    [{"url": "test-url.com"}, {"url": "test2-url.com"}]
                ),
                "worker_config": json.dumps("test"),
            },
            [{"url": "test-url.com"}, {"url": "test2-url.com"}],
        ),
    ),
)
def test_get_remote_write_endpoints(remote_databag, expected):
    ctx = Context(
        MyCharm,
        meta={
            "name": "foo",
            "requires": {"cluster": {"interface": "cluster"}},
            "containers": {"foo": {"type": "oci-image"}},
        },
        config={"options": {"role-all": {"type": "boolean", "default": True}}},
    )
    container = Container(
        "foo",
        exec_mock={("update-ca-certificates", "--fresh"): ExecOutput()},
        can_connect=True,
    )
    relation = Relation(
        "cluster",
        remote_app_data=remote_databag,
    )
    with ctx.manager(
        relation.changed_event, State(containers=[container], relations=[relation])
    ) as mgr:
        charm = mgr.charm
        mgr.run()
        assert charm.worker.cluster.get_remote_write_endpoints() == expected


def test_config_preprocessor():
    # GIVEN a charm with a config preprocessor
    new_config = {"modified": "config"}

    class MyWorker(Worker):

        @property
        def _worker_config(self):
            # mock config processor that entirely replaces the config with another,
            # normally one would call super and manipulate
            return new_config

    class MyCharm(ops.CharmBase):
        layer = Layer({"services": {"foo": {"command": ["bar"]}}})

        def __init__(self, framework: Framework):
            super().__init__(framework)
            self.worker = MyWorker(
                self,
                "foo",
                lambda _: self.layer,
                {"cluster": "cluster"},
            )

    ctx = Context(
        MyCharm,
        meta={
            "name": "foo",
            "requires": {"cluster": {"interface": "cluster"}},
            "containers": {"foo": {"type": "oci-image"}},
        },
        config={
            "options": {
                "role-all": {"type": "boolean", "default": "true"},
                "role-none": {"type": "boolean", "default": "false"},
            }
        },
    )

    # WHEN the charm writes the config to disk
    state_out = ctx.run(
        "config_changed",
        State(
            config={"role-all": True},
            containers=[
                Container(
                    "foo",
                    can_connect=True,
                    exec_mock={("update-ca-certificates", "--fresh"): ExecOutput()},
                )
            ],
            relations=[
                Relation(
                    "cluster",
                    remote_app_data={
                        "worker_config": json.dumps(yaml.safe_dump({"original": "config"}))
                    },
                )
            ],
        ),
    )

    # THEN the data gets preprocessed
    fs = Path(str(state_out.get_container("foo").get_filesystem(ctx)) + CONFIG_FILE)
    assert fs.read_text() == yaml.safe_dump(new_config)
