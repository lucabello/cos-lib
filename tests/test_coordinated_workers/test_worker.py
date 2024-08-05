import ops
import pytest
from cosl.coordinated_workers.worker import Worker
from ops import Framework
from ops.pebble import Layer
from scenario import Container, Context, State
from scenario.runtime import UncaughtCharmError


class MyCharm(ops.CharmBase):
    def __init__(self, framework: Framework):
        super().__init__(framework)
        self.worker = Worker(self, "foo", lambda _: Layer(""), {"cluster": "cluster"})


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
