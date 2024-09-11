import ops
import pytest
from ops import Framework
from scenario import Container, Context, Relation, State

from src.cosl.coordinated_workers.coordinator import (
    ClusterRolesConfig,
    Coordinator,
    S3NotFoundError,
)
from src.cosl.coordinated_workers.interface import ClusterRequirerAppData


@pytest.fixture
def coordinator_state():
    requires_relations = {
        endpoint: Relation(endpoint=endpoint, interface=interface["interface"])
        for endpoint, interface in {
            "my-certificates": {"interface": "certificates"},
            "my-logging": {"interface": "loki_push_api"},
            "my-tracing": {"interface": "tracing"},
        }.items()
    }
    requires_relations["my-s3"] = Relation(
        "my-s3",
        interface="s3",
        remote_app_data={
            "endpoint": "s3",
            "bucket": "foo-bucket",
            "access-key": "my-access-key",
            "secret-key": "my-secret-key",
        },
    )
    requires_relations["cluster_worker0"] = Relation(
        "my-cluster",
        remote_app_name="worker0",
        remote_app_data=ClusterRequirerAppData(role="read").dump(),
    )
    requires_relations["cluster_worker1"] = Relation(
        "my-cluster",
        remote_app_name="worker1",
        remote_app_data=ClusterRequirerAppData(role="write").dump(),
    )
    requires_relations["cluster_worker2"] = Relation(
        "my-cluster",
        remote_app_name="worker2",
        remote_app_data=ClusterRequirerAppData(role="backend").dump(),
    )

    provides_relations = {
        endpoint: Relation(endpoint=endpoint, interface=interface["interface"])
        for endpoint, interface in {
            "my-dashboards": {"interface": "grafana_dashboard"},
            "my-metrics": {"interface": "prometheus_scrape"},
        }.items()
    }

    return State(
        containers=[
            Container("nginx", can_connect=True),
            Container("nginx-prometheus-exporter", can_connect=True),
        ],
        relations=list(requires_relations.values()) + list(provides_relations.values()),
    )


@pytest.fixture()
def coordinator_charm(request):
    class MyCoordinator(ops.CharmBase):
        META = {
            "name": "foo-app",
            "requires": {
                "my-certificates": {"interface": "certificates"},
                "my-cluster": {"interface": "cluster"},
                "my-logging": {"interface": "loki_push_api"},
                "my-tracing": {"interface": "tracing"},
                "my-s3": {"interface": "s3"},
            },
            "provides": {
                "my-dashboards": {"interface": "grafana_dashboard"},
                "my-metrics": {"interface": "prometheus_scrape"},
            },
            "containers": {
                "nginx": {"type": "oci-image"},
                "nginx-prometheus-exporter": {"type": "oci-image"},
            },
        }

        def __init__(self, framework: Framework):
            super().__init__(framework)
            # Note: Here it is a good idea not to use context mgr because it is "ops aware"
            self.coordinator = Coordinator(
                charm=self,
                # Roles were take from loki-coordinator-k8s-operator
                roles_config=ClusterRolesConfig(
                    roles={"all", "read", "write", "backend"},
                    meta_roles={"all": {"all", "read", "write", "backend"}},
                    minimal_deployment={
                        "read",
                        "write",
                        "backend",
                    },
                    recommended_deployment={
                        "read": 3,
                        "write": 3,
                        "backend": 3,
                    },
                ),
                external_url="https://foo.example.com",
                worker_metrics_port=123,
                endpoints={
                    "certificates": "my-certificates",
                    "cluster": "my-cluster",
                    "grafana-dashboards": "my-dashboards",
                    "logging": "my-logging",
                    "metrics": "my-metrics",
                    "tracing": "my-tracing",
                    "s3": "my-s3",
                },
                nginx_config=lambda coordinator: f"nginx configuration for {coordinator.name}",
                workers_config=lambda coordinator: f"workers configuration for {coordinator.name}",
                # nginx_options: Optional[NginxMappingOverrides] = None,
                # is_coherent: Optional[Callable[[ClusterProvider, ClusterRolesConfig], bool]] = None,
                # is_recommended: Optional[Callable[[ClusterProvider, ClusterRolesConfig], bool]] = None,
                # tracing_receivers: Optional[Callable[[], Optional[Dict[str, str]]]] = None,
            )

    return MyCoordinator


def test_worker_roles_subset_of_minimal_deployment(
    coordinator_state: State, coordinator_charm: ops.CharmBase
):
    # Test that the combination of worker roles is a subset of the minimal deployment roles

    # GIVEN a coordinator_charm
    ctx = Context(coordinator_charm, meta=coordinator_charm.META)

    # AND a coordinator_state defining relations to worker charms with incomplete distributed roles
    missing_backend_worker_relation = [
        relation
        for relation in coordinator_state.relations
        if relation.remote_app_name != "worker2"
    ]

    # WHEN we process any event
    with ctx.manager(
        "update-status",
        state=coordinator_state.replace(relations=missing_backend_worker_relation),
    ) as mgr:
        charm: coordinator_charm = mgr.charm

        # THEN the deployment is coherent
        assert not charm.coordinator.is_coherent


def test_without_s3_integration_raises_error(
    coordinator_state: State, coordinator_charm: ops.CharmBase
):
    # Test that a charm without an s3 integration raises S3NotFoundError

    # GIVEN a coordinator charm without an s3 integration
    ctx = Context(coordinator_charm, meta=coordinator_charm.META)
    relations_without_s3 = [
        relation for relation in coordinator_state.relations if relation.endpoint != "my-s3"
    ]

    # WHEN we process any event
    with ctx.manager(
        "update-status",
        state=coordinator_state.replace(relations=relations_without_s3),
    ) as mgr:
        # THEN the _s3_config method raises and S3NotFoundError
        with pytest.raises(S3NotFoundError):
            mgr.charm.coordinator._s3_config
