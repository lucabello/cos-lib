import dataclasses
import json

import ops
import pytest
from ops import testing

from src.cosl.coordinated_workers.coordinator import (
    ClusterRolesConfig,
    Coordinator,
    S3NotFoundError,
)
from src.cosl.coordinated_workers.interface import ClusterRequirerAppData


@pytest.fixture
def coordinator_state():
    requires_relations = {
        endpoint: testing.Relation(endpoint=endpoint, interface=interface["interface"])
        for endpoint, interface in {
            "my-certificates": {"interface": "certificates"},
            "my-logging": {"interface": "loki_push_api"},
            "my-charm-tracing": {"interface": "tracing"},
            "my-workload-tracing": {"interface": "tracing"},
        }.items()
    }
    requires_relations["my-s3"] = testing.Relation(
        "my-s3",
        interface="s3",
        remote_app_data={
            "endpoint": "s3",
            "bucket": "foo-bucket",
            "access-key": "my-access-key",
            "secret-key": "my-secret-key",
        },
    )
    requires_relations["cluster_worker0"] = testing.Relation(
        "my-cluster",
        remote_app_name="worker0",
        remote_app_data=ClusterRequirerAppData(role="read").dump(),
    )
    requires_relations["cluster_worker1"] = testing.Relation(
        "my-cluster",
        remote_app_name="worker1",
        remote_app_data=ClusterRequirerAppData(role="write").dump(),
    )
    requires_relations["cluster_worker2"] = testing.Relation(
        "my-cluster",
        remote_app_name="worker2",
        remote_app_data=ClusterRequirerAppData(role="backend").dump(),
    )

    provides_relations = {
        endpoint: testing.Relation(endpoint=endpoint, interface=interface["interface"])
        for endpoint, interface in {
            "my-dashboards": {"interface": "grafana_dashboard"},
            "my-metrics": {"interface": "prometheus_scrape"},
        }.items()
    }

    return testing.State(
        containers={
            testing.Container("nginx", can_connect=True),
            testing.Container("nginx-prometheus-exporter", can_connect=True),
        },
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
                "my-charm-tracing": {"interface": "tracing", "limit": 1},
                "my-workload-tracing": {"interface": "tracing", "limit": 1},
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

        def __init__(self, framework: ops.Framework):
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
                    "charm-tracing": "my-charm-tracing",
                    "workload-tracing": "my-workload-tracing",
                    "s3": "my-s3",
                },
                nginx_config=lambda coordinator: f"nginx configuration for {coordinator._charm.meta.name}",
                workers_config=lambda coordinator: f"workers configuration for {coordinator._charm.meta.name}",
                # nginx_options: Optional[NginxMappingOverrides] = None,
                # is_coherent: Optional[Callable[[ClusterProvider, ClusterRolesConfig], bool]] = None,
                # is_recommended: Optional[Callable[[ClusterProvider, ClusterRolesConfig], bool]] = None,
            )

    return MyCoordinator


def test_worker_roles_subset_of_minimal_deployment(
    coordinator_state: testing.State, coordinator_charm: ops.CharmBase
):
    # Test that the combination of worker roles is a subset of the minimal deployment roles

    # GIVEN a coordinator_charm
    ctx = testing.Context(coordinator_charm, meta=coordinator_charm.META)

    # AND a coordinator_state defining relations to worker charms with incomplete distributed roles
    missing_backend_worker_relation = {
        relation
        for relation in coordinator_state.relations
        if relation.remote_app_name != "worker2"
    }

    # WHEN we process any event
    with ctx(
        ctx.on.update_status(),
        state=dataclasses.replace(coordinator_state, relations=missing_backend_worker_relation),
    ) as mgr:
        charm: coordinator_charm = mgr.charm

        # THEN the deployment is not coherent
        assert not charm.coordinator.is_coherent


def test_without_s3_integration_raises_error(
    coordinator_state: testing.State, coordinator_charm: ops.CharmBase
):
    # Test that a charm without an s3 integration raises S3NotFoundError

    # GIVEN a coordinator charm without an s3 integration
    ctx = testing.Context(coordinator_charm, meta=coordinator_charm.META)
    relations_without_s3 = {
        relation for relation in coordinator_state.relations if relation.endpoint != "my-s3"
    }

    # WHEN we process any event
    with ctx(
        ctx.on.update_status(),
        state=dataclasses.replace(coordinator_state, relations=relations_without_s3),
    ) as mgr:
        # THEN the _s3_config method raises an S3NotFoundError
        with pytest.raises(S3NotFoundError):
            mgr.charm.coordinator._s3_config


@pytest.mark.parametrize("region", (None, "canada"))
@pytest.mark.parametrize("tls_ca_chain", (None, ["my ca chain"]))
@pytest.mark.parametrize("bucket", ("bucky",))
@pytest.mark.parametrize("secret_key", ("foo",))
@pytest.mark.parametrize("access_key", ("foo",))
@pytest.mark.parametrize(
    "endpoint, endpoint_stripped",
    (
        ("example.com", "example.com"),
        ("http://example.com", "example.com"),
        ("https://example.com", "example.com"),
    ),
)
def test_s3_integration(
    coordinator_state: testing.State,
    coordinator_charm: ops.CharmBase,
    region,
    endpoint,
    endpoint_stripped,
    secret_key,
    access_key,
    bucket,
    tls_ca_chain,
):
    # Test that a charm with a s3 integration gives the expected _s3_config

    # GIVEN a coordinator charm with a s3 integration
    ctx = testing.Context(coordinator_charm, meta=coordinator_charm.META)
    s3_relation = coordinator_state.get_relations("my-s3")[0]
    relations_except_s3 = [
        relation for relation in coordinator_state.relations if relation.endpoint != "my-s3"
    ]
    s3_app_data = {
        k: json.dumps(v)
        for k, v in {
            **({"region": region} if region else {}),
            **({"tls-ca-chain": tls_ca_chain} if tls_ca_chain else {}),
            "endpoint": endpoint,
            "access-key": access_key,
            "secret-key": secret_key,
            "bucket": bucket,
        }.items()
    }

    # WHEN we process any event
    with ctx(
        ctx.on.update_status(),
        state=dataclasses.replace(
            coordinator_state,
            relations=relations_except_s3
            + [dataclasses.replace(s3_relation, remote_app_data=s3_app_data)],
        ),
    ) as mgr:
        # THEN the s3_connection_info method returns the expected data structure
        coordinator: Coordinator = mgr.charm.coordinator
        assert coordinator.s3_connection_info.region == region
        assert coordinator.s3_connection_info.bucket == bucket
        assert coordinator.s3_connection_info.endpoint == endpoint
        assert coordinator.s3_connection_info.secret_key == secret_key
        assert coordinator.s3_connection_info.access_key == access_key
        assert coordinator.s3_connection_info.tls_ca_chain == tls_ca_chain
        assert coordinator._s3_config["endpoint"] == endpoint_stripped
        assert coordinator._s3_config["insecure"] is (not tls_ca_chain)


def test_tracing_receivers_urls(
    coordinator_state: testing.State, coordinator_charm: ops.CharmBase
):
    charm_tracing_relation = testing.Relation(
        endpoint="my-charm-tracing",
        remote_app_data={
            "receivers": json.dumps(
                [{"protocol": {"name": "otlp_http", "type": "http"}, "url": "1.2.3.4:4318"}]
            )
        },
    )
    workload_tracing_relation = testing.Relation(
        endpoint="my-workload-tracing",
        remote_app_data={
            "receivers": json.dumps(
                [
                    {"protocol": {"name": "otlp_http", "type": "http"}, "url": "5.6.7.8:4318"},
                    {"protocol": {"name": "otlp_grpc", "type": "grpc"}, "url": "5.6.7.8:4317"},
                ]
            )
        },
    )
    ctx = testing.Context(coordinator_charm, meta=coordinator_charm.META)
    with ctx(
        ctx.on.update_status(),
        state=dataclasses.replace(
            coordinator_state, relations=[charm_tracing_relation, workload_tracing_relation]
        ),
    ) as mgr:
        coordinator: Coordinator = mgr.charm.coordinator
        assert coordinator._charm_tracing_receivers_urls == {
            "otlp_http": "1.2.3.4:4318",
        }
        assert coordinator._workload_tracing_receivers_urls == {
            "otlp_http": "5.6.7.8:4318",
            "otlp_grpc": "5.6.7.8:4317",
        }
