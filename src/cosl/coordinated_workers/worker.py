#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Generic worker for a distributed charm deployment."""

import logging
import re
import socket
import subprocess
import urllib.request
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TypedDict, Union

import ops
import tenacity
import yaml
from ops import MaintenanceStatus
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Check, Layer, PathError, Plan, ProtocolError

from cosl import JujuTopology
from cosl.coordinated_workers.interface import ClusterRequirer
from cosl.helpers import check_libs_installed

check_libs_installed(
    "charms.loki_k8s.v1.loki_push_api",
    "charms.observability_libs.v0.kubernetes_compute_resources_patch",
)

from charms.loki_k8s.v1.loki_push_api import _PebbleLogClient  # type: ignore
from charms.observability_libs.v0.kubernetes_compute_resources_patch import (
    KubernetesComputeResourcesPatch,
    adjust_resource_requirements,
)
from lightkube.models.core_v1 import ResourceRequirements

BASE_DIR = "/worker"
CONFIG_FILE = "/etc/worker/config.yaml"
CERT_FILE = "/etc/worker/server.cert"
KEY_FILE = "/etc/worker/private.key"
CLIENT_CA_FILE = "/etc/worker/ca.cert"

logger = logging.getLogger(__name__)


def _validate_container_name(
    container_name: Optional[str],
    resources_requests: Optional[Callable[["Worker"], Dict[str, str]]],
):
    """Raise `ValueError` if `resources_requests` is not None and `container_name` is None."""
    if resources_requests is not None and container_name is None:
        raise ValueError(
            "Cannot have a None value for container_name while resources_requests is provided."
        )


_EndpointMapping = TypedDict("_EndpointMapping", {"cluster": str}, total=True)
"""Mapping of the relation endpoint names that the charms uses, as defined in metadata.yaml."""

_ResourceLimitOptionsMapping = TypedDict(
    "_ResourceLimitOptionsMapping",
    {
        "cpu_limit": str,
        "memory_limit": str,
    },
)
"""Mapping of the resources limit option names that the charms use, as defined in config.yaml."""


ROOT_CA_CERT = Path("/usr/local/share/ca-certificates/ca.crt")


class WorkerError(Exception):
    """Base class for exceptions raised by this module."""


class ServiceEndpointStatus(Enum):
    """Status of the worker service managed by pebble."""

    starting = "starting"
    up = "up"
    down = "down"


class Worker(ops.Object):
    """Charming worker."""

    _endpoints: _EndpointMapping = {
        "cluster": "cluster",
    }

    def __init__(
        self,
        charm: ops.CharmBase,
        name: str,
        pebble_layer: Callable[["Worker"], Layer],
        endpoints: _EndpointMapping,
        readiness_check_endpoint: Optional[Union[str, Callable[["Worker"], str]]] = None,
        resources_limit_options: Optional[_ResourceLimitOptionsMapping] = None,
        resources_requests: Optional[Callable[["Worker"], Dict[str, str]]] = None,
        container_name: Optional[str] = None,
    ):
        """Constructor for a Worker object.

        Args:
            charm: The worker charm object.
            name: The name of the workload container.
            pebble_layer: The pebble layer of the workload.
            endpoints: Endpoint names for coordinator relations, as defined in metadata.yaml.
            readiness_check_endpoint: URL to probe with a pebble check to determine
                whether the worker node is ready. Passing None will effectively disable it.
            resources_limit_options: A dictionary containing resources limit option names. The dictionary should include
                "cpu_limit" and "memory_limit" keys with values as option names, as defined in the config.yaml.
                If no dictionary is provided, the default option names "cpu_limit" and "memory_limit" would be used.
            resources_requests: A function generating the resources "requests" portion to apply when patching a container using
                KubernetesComputeResourcesPatch. The "limits" portion of the patch gets populated by setting
                their respective config options in config.yaml.
            container_name: The container for which to apply the resources requests & limits.
                Required if `resources_requests` is provided.

        Raises:
        ValueError:
            If `resources_requests` is not None and `container_name` is None, a ValueError is raised.
        """
        super().__init__(charm, key="worker")
        self._charm = charm
        self._name = name
        self._pebble_layer = partial(pebble_layer, self)
        self.topology = JujuTopology.from_charm(self._charm)
        self._container = self._charm.unit.get_container(name)

        self._endpoints = endpoints
        _validate_container_name(container_name, resources_requests)

        # turn str to Callable[[Worker], str]
        self._readiness_check_endpoint: Optional[Callable[[Worker], str]]
        if isinstance(readiness_check_endpoint, str):
            self._readiness_check_endpoint = lambda _: readiness_check_endpoint
        else:
            self._readiness_check_endpoint = readiness_check_endpoint
        self._resources_requests_getter = (
            partial(resources_requests, self) if resources_requests is not None else None
        )
        self._container_name = container_name
        self._resources_limit_options = resources_limit_options or {}

        self.cluster = ClusterRequirer(
            charm=self._charm,
            endpoint=self._endpoints["cluster"],
        )

        self._log_forwarder = ManualLogForwarder(
            charm=self._charm,
            loki_endpoints=self.cluster.get_loki_endpoints(),
            refresh_events=[
                self.cluster.on.config_received,
                self.cluster.on.created,
                self.cluster.on.removed,
            ],
        )

        # Resources patch
        self.resources_patch = (
            KubernetesComputeResourcesPatch(
                self._charm,
                self._container_name,  # type: ignore
                resource_reqs_func=self._adjust_resource_requirements,
            )
            if self._resources_requests_getter
            else None
        )

        # Event listeners
        self.framework.observe(self._charm.on.config_changed, self._on_config_changed)
        self.framework.observe(self._charm.on.upgrade_charm, self._on_upgrade_charm)
        self.framework.observe(self._charm.on.collect_unit_status, self._on_collect_status)

        self.framework.observe(self.cluster.on.config_received, self._on_worker_config_received)
        self.framework.observe(self.cluster.on.created, self._on_cluster_created)
        self.framework.observe(self.cluster.on.removed, self._log_forwarder.disable_logging)

        self.framework.observe(self._charm.on[self._name].pebble_ready, self._on_pebble_ready)
        self.framework.observe(
            self._charm.on[name].pebble_check_failed, self._on_pebble_check_failed
        )
        self.framework.observe(
            self._charm.on[name].pebble_check_recovered, self._on_pebble_check_recovered
        )

    # Event handlers
    def _on_pebble_ready(self, _: ops.PebbleReadyEvent):
        self._charm.unit.set_workload_version(self.running_version() or "")
        self._update_config()

    def _on_pebble_check_failed(self, event: ops.PebbleCheckFailedEvent):
        if event.info.name == "ready":
            logger.warning("Pebble `ready` check started to fail: " "worker node is down.")
            # collect-status will detect that we're not ready and set waiting status.

    def _on_pebble_check_recovered(self, event: ops.PebbleCheckFailedEvent):
        if event.info.name == "ready":
            logger.info("Pebble `ready` check is now passing: " "worker node is up.")
            # collect-status will detect that we're ready and set active status.

    def _on_worker_config_received(self, _: ops.EventBase):
        self._update_config()

    def _on_upgrade_charm(self, _: ops.UpgradeCharmEvent):
        self._update_cluster_relation()

    def _on_cluster_created(self, _: ops.EventBase):
        self._update_cluster_relation()
        self._update_config()

    def _on_cluster_changed(self, _: ops.EventBase):
        self._update_config()

    def _on_config_changed(self, _: ops.ConfigChangedEvent):
        # If the user has changed roles, publish them to relation data
        self._update_cluster_relation()
        # If there is a config, start the worker
        if self._worker_config:
            self._update_worker_config()

    @property
    def _worker_config(self):
        """The configuration that this worker should run with, as received from the coordinator.

        Charms that wish to modify their config before it's written to disk by the Worker
        should subclass the worker, override this method, and use it to manipulate the
        config that's presented to the Worker.
        """
        return self.cluster.get_worker_config()

    @property
    def status(self) -> ServiceEndpointStatus:
        """Determine the status of the service's endpoint."""
        check_endpoint = self._readiness_check_endpoint
        if not check_endpoint:
            raise WorkerError(
                "cannot check readiness without a readiness_check_endpoint configured. "
                "Pass one to Worker on __init__."
            )

        if not self._container.can_connect():
            logger.debug("Container cannot connect. Skipping status check.")
            return ServiceEndpointStatus.down

        if not self._running_worker_config():
            logger.debug("Config file not on disk. Skipping status check.")
            return ServiceEndpointStatus.down

        # we really don't want this code to raise errors, so we blanket catch all.
        try:
            layer: Layer = self._pebble_layer()
            services = self._container.get_services(*layer.services.keys())
            running_status = {name: svc.is_running() for name, svc in services.items()}
            if not all(running_status.values()):
                if any(running_status.values()):
                    starting_services = tuple(
                        name for name, running in running_status.items() if not running
                    )
                    logger.info(f"Some services are not running: {starting_services}.")
                    return ServiceEndpointStatus.starting

                logger.info("All services are down.")
                return ServiceEndpointStatus.down

            with urllib.request.urlopen(check_endpoint(self)) as response:
                html: bytes = response.read()

            # ready response should simply be a string:
            #   "ready"
            raw_out = html.decode("utf-8").strip()
            if raw_out == "ready":
                return ServiceEndpointStatus.up

            # depending on the workload, we get something like:
            #   Some services are not Running:
            #   Starting: 1
            #   Running: 16
            # (tempo)
            #   Ingester not ready: waiting for 15s after being ready
            # (mimir)

            # anything that isn't 'ready' but also is a 2xx response will be interpreted as:
            # we're not ready yet, but we're working on it.
            logger.debug(f"GET {check_endpoint} returned: {raw_out!r}.")
            return ServiceEndpointStatus.starting

        except Exception:
            logger.exception(
                "Error while getting worker status. "
                "This could mean that the worker is still starting."
            )
            return ServiceEndpointStatus.down

    def _on_collect_status(self, e: ops.CollectStatusEvent):
        if self.resources_patch and self.resources_patch.get_status().name != "active":
            e.add_status(self.resources_patch.get_status())

        if not self._container.can_connect():
            e.add_status(WaitingStatus(f"Waiting for `{self._name}` container"))
        if not self.model.get_relation(self._endpoints["cluster"]):
            e.add_status(BlockedStatus("Missing relation to a coordinator charm"))
        elif not self.cluster.relation:
            e.add_status(WaitingStatus("Cluster relation not ready"))
        if not self._worker_config:
            e.add_status(WaitingStatus("Waiting for coordinator to publish a config"))
        if not self.roles:
            e.add_status(
                BlockedStatus("Invalid or no roles assigned: please configure some valid roles")
            )

        try:
            status = self.status
            if status == ServiceEndpointStatus.starting:
                e.add_status(WaitingStatus("Starting..."))
            elif status == ServiceEndpointStatus.down:
                e.add_status(BlockedStatus("node down (see logs)"))
        except WorkerError:
            logger.debug("Unable to determine worker readiness: no endpoint given.")

        e.add_status(
            ActiveStatus(
                "(all roles) ready."
                if ",".join(self.roles) == "all"
                else f"{','.join(self.roles)} ready."
            )
        )

    # Utility functions
    @property
    def roles(self) -> List[str]:
        """Return a list of the roles this worker should take on.

        Expects that the charm defines a set of roles by config like:
            "role-a": bool
            "role-b": bool
            "role-b": bool
        If this is not the case, it will raise an error.
        """
        config = self._charm.config

        role_config_options = [option for option in config.keys() if option.startswith("role-")]
        if not role_config_options:
            raise WorkerError(
                "The charm should define a set of `role-X` config "
                "options for it to use the Worker."
            )

        active_roles: List[str] = [
            role[5:] for role in role_config_options if config[role] is True
        ]
        return active_roles

    def _update_config(self) -> None:
        """Update the worker config and restart the workload if necessary."""
        restart = any(
            (
                self._update_tls_certificates(),
                self._update_worker_config(),
                self._set_pebble_layer(),
            )
        )

        if restart:
            logger.debug("Config changed. Restarting worker services...")
            self.restart()

        # this can happen if s3 wasn't ready (server gave error) when we processed an earlier event
        # causing the worker service to die on startup (exited quickly with code...)
        # so we try to restart it now.
        # TODO: would be nice if we could be notified of when s3 starts working, so we don't have to
        #  wait for an update-status and can listen to that instead.
        elif not all(svc.is_running() for svc in self._container.get_services().values()):
            logger.debug("Some services are not running. Starting them now...")
            self.restart()

    def _set_pebble_layer(self) -> bool:
        """Set Pebble layer.

        Returns: True if Pebble layer was added, otherwise False.
        """
        if not self._container.can_connect():
            return False
        if not self.roles:
            return False

        current_plan = self._container.get_plan()
        new_layer = self._pebble_layer()
        self._add_readiness_check(new_layer)

        def diff(layer: Layer, plan: Plan):
            layer_dct = layer.to_dict()
            plan_dct = plan.to_dict()
            for key in ["checks", "services"]:
                if layer_dct.get(key) != plan_dct.get(key):
                    return True
            return False

        if diff(new_layer, current_plan):
            logger.debug("Adding new layer to pebble...")
            self._container.add_layer(self._name, new_layer, combine=True)
            return True
        return False

    def _add_readiness_check(self, new_layer: Layer):
        """Add readiness check to a pebble layer."""
        if not self._readiness_check_endpoint:
            # skip
            return

        new_layer.checks["ready"] = Check(
            "ready", {"override": "replace", "http": {"url": self._readiness_check_endpoint(self)}}
        )

    def _update_cluster_relation(self) -> None:
        """Publish all the worker information to relation data."""
        self.cluster.publish_unit_address(socket.getfqdn())
        if self._charm.unit.is_leader() and self.roles:
            logger.info(f"publishing roles: {self.roles}")
            self.cluster.publish_app_roles(self.roles)

        if self._worker_config:
            self._update_config()

    def _running_worker_config(self) -> Optional[Dict[str, Any]]:
        """Return the worker config as dict, or None if retrieval failed."""
        if not self._container.can_connect():
            logger.debug("Could not connect to the workload container")
            return None

        try:
            raw_current = self._container.pull(CONFIG_FILE).read()
            return yaml.safe_load(raw_current)
        except (ProtocolError, PathError) as e:
            logger.warning(
                "Could not check the current worker configuration due to "
                "a failure in retrieving the file: %s",
                e,
            )
            return None

    def _update_worker_config(self) -> bool:
        """Set worker config for the workload.

        Returns: True if config has changed, otherwise False.
        Raises: BlockedStatusError exception if PebbleError, ProtocolError, PathError exceptions
            are raised by container.remove_path
        """
        if not self._container.can_connect():
            logger.warning("cannot update worker config: container cannot connect.")
            return False

        if len(self.roles) == 0:
            logger.warning("cannot update worker config: role missing or misconfigured.")
            return False

        worker_config = self._worker_config
        if not worker_config:
            logger.warning("cannot update worker config: coordinator hasn't published one yet.")
            return False

        if self._running_worker_config() != worker_config:
            config_as_yaml = yaml.safe_dump(worker_config)
            self._container.push(CONFIG_FILE, config_as_yaml, make_dirs=True)
            logger.info("Pushed new worker configuration")
            return True

        return False

    def _update_tls_certificates(self) -> bool:
        """Update the TLS certificates on disk according to their availability."""
        if not self._container.can_connect():
            return False

        if tls_data := self.cluster.get_tls_data():
            private_key_secret = self.model.get_secret(id=tls_data["privkey_secret_id"])
            private_key = private_key_secret.get_content().get("private-key")

            ca_cert = tls_data["ca_cert"]
            server_cert = tls_data["server_cert"]

            # Save the workload certificates
            self._container.push(CERT_FILE, server_cert or "", make_dirs=True)
            self._container.push(KEY_FILE, private_key or "", make_dirs=True)
            self._container.push(CLIENT_CA_FILE, ca_cert or "", make_dirs=True)
            self._container.push(ROOT_CA_CERT, ca_cert or "", make_dirs=True)

            # Save the cacert in the charm container for charm traces
            ROOT_CA_CERT.write_text(ca_cert)
        else:
            self._container.remove_path(CERT_FILE, recursive=True)
            self._container.remove_path(KEY_FILE, recursive=True)
            self._container.remove_path(CLIENT_CA_FILE, recursive=True)
            self._container.remove_path(ROOT_CA_CERT, recursive=True)

            # Remove from charm container
            ROOT_CA_CERT.unlink(missing_ok=True)

        # FIXME: uncomment as soon as the nginx image contains the ca-certificates package
        self._container.exec(["update-ca-certificates", "--fresh"]).wait()
        subprocess.run(["update-ca-certificates", "--fresh"])

        return True

    SERVICE_START_RETRY_STOP = tenacity.stop_after_delay(60 * 15)
    SERVICE_START_RETRY_WAIT = tenacity.wait_fixed(60)
    SERVICE_START_RETRY_IF = tenacity.retry_if_exception_type(ops.pebble.ChangeError)

    def restart(self):
        """Restart the pebble service or start it if not already running.

        Default timeout is 15 minutes. Configure it by setting this class attr:
        >>> Worker.SERVICE_START_RETRY_STOP = tenacity.stop_after_delay(60 * 30)  # 30 minutes
        You can also configure SERVICE_START_RETRY_WAIT and SERVICE_START_RETRY_IF.

        This method will raise an exception if it fails to start the service within a
        specified timeframe. This will presumably bring the charm in error status, so
        that juju will retry the last emitted hook until it finally succeeds.

        The assumption is that the state we are in when this method is called is consistent.
        The reason why we're failing to restart is dependent on some external factor (such as network,
        the reachability of a remote API, or the readiness of an external service the workload depends on).
        So letting juju retry the same hook will get us unstuck as soon as that contingency is resolved.

        See https://discourse.charmhub.io/t/its-probably-ok-for-a-unit-to-go-into-error-state/13022
        """
        if not self._container.exists(CONFIG_FILE):
            logger.error("cannot restart worker: config file doesn't exist (yet).")
            return
        if not self.roles:
            logger.debug("cannot restart worker: no roles have been configured.")
            return

        try:
            for attempt in tenacity.Retrying(
                # this method may fail with ChangeError (exited quickly with code...)
                retry=self.SERVICE_START_RETRY_IF,
                # give this method some time to pass (by default 15 minutes)
                stop=self.SERVICE_START_RETRY_STOP,
                # wait 1 minute between tries
                wait=self.SERVICE_START_RETRY_WAIT,
                # if you don't succeed raise the last caught exception when you're done
                reraise=True,
            ):
                with attempt:
                    self._charm.unit.status = MaintenanceStatus(
                        f"restarting... (attempt #{attempt.retry_state.attempt_number})"
                    )
                    # restart all services that our layer is responsible for
                    self._container.restart(*self._pebble_layer().services.keys())

        except ops.pebble.ChangeError:
            logger.error(
                "failed to (re)start worker jobs. This usually means that an external resource (such as s3) "
                "that the software needs to start is not available."
            )
            raise

    def running_version(self) -> Optional[str]:
        """Get the running version from the worker process."""
        if not self._container.can_connect():
            return None

        version_output, _ = self._container.exec([f"/bin/{self._name}", "-version"]).wait_output()
        # Output looks like this:
        # <WORKLOAD_NAME>, version 2.4.0 (branch: HEAD, revision 32137ee...)
        if result := re.search(r"[Vv]ersion:?\s*(\S+)", version_output):
            return result.group(1)
        return None

    def charm_tracing_config(self) -> Tuple[Optional[str], Optional[str]]:
        """Get the charm tracing configuration from the coordinator.

        Usage:
          assuming you are using charm_tracing >= v1.9:
        >>> from ops import CharmBase
        >>> from lib.charms.tempo_k8s.v1.charm_tracing import trace_charm
        >>> from lib.charms.tempo_k8s.v2.tracing import charm_tracing_config
        >>> @trace_charm(tracing_endpoint="my_endpoint", cert_path="cert_path")
        >>> class MyCharm(CharmBase):
        >>>     def __init__(self, ...):
        >>>         self.worker = Worker(...)
        >>>         self.my_endpoint, self.cert_path = self.worker.charm_tracing_config()
        """
        receivers = self.cluster.get_tracing_receivers()

        if not receivers:
            return None, None

        endpoint = receivers.get("otlp_http")
        if not endpoint:
            return None, None

        is_https = endpoint.startswith("https://")

        tls_data = self.cluster.get_tls_data()
        server_ca_cert = tls_data.get("server_cert") if tls_data else None

        if is_https:
            if server_ca_cert is None:
                raise RuntimeError(
                    "Cannot send traces to an https endpoint without a certificate."
                )
            elif not ROOT_CA_CERT.exists():
                # if endpoint is https and we have a tls integration BUT we don't have the
                # server_cert on disk yet (this could race with _update_tls_certificates):
                # put it there and proceed
                ROOT_CA_CERT.parent.mkdir(parents=True, exist_ok=True)
                ROOT_CA_CERT.write_text(server_ca_cert)

            return endpoint, str(ROOT_CA_CERT)
        else:
            return endpoint, None

    def _adjust_resource_requirements(self) -> ResourceRequirements:
        """A method that gets called by `KubernetesComputeResourcesPatch` to adjust the resources requests and limits to patch."""
        cpu_limit_key = self._resources_limit_options.get("cpu_limit", "cpu_limit")
        memory_limit_key = self._resources_limit_options.get("memory_limit", "memory_limit")

        limits = {
            "cpu": self._charm.model.config.get(cpu_limit_key),
            "memory": self._charm.model.config.get(memory_limit_key),
        }
        return adjust_resource_requirements(
            limits, self._resources_requests_getter(), adhere_to_requests=True  # type: ignore
        )


class ManualLogForwarder(ops.Object):
    """Forward the standard outputs of all workloads to explictly-provided Loki endpoints."""

    def __init__(
        self,
        charm: ops.CharmBase,
        *,
        loki_endpoints: Optional[Dict[str, str]],
        refresh_events: Optional[List[ops.BoundEvent]] = None,
    ):
        _PebbleLogClient.check_juju_version()
        super().__init__(charm, "worker-log-forwarder")
        self._charm = charm
        self._loki_endpoints = loki_endpoints
        self._topology: JujuTopology = JujuTopology.from_charm(charm)

        if not refresh_events:
            return

        for event in refresh_events:
            self.framework.observe(event, self.update_logging)

    def update_logging(self, _: Optional[ops.EventBase] = None):
        """Update the log forwarding to match the active Loki endpoints."""
        loki_endpoints = self._loki_endpoints

        if not loki_endpoints:
            logger.warning("No Loki endpoints available")
            loki_endpoints = {}

        for container in self._charm.unit.containers.values():
            if container.can_connect():
                _PebbleLogClient.disable_inactive_endpoints(  # type:ignore
                    container=container,
                    active_endpoints=loki_endpoints,
                    topology=self._topology,
                )
                _PebbleLogClient.enable_endpoints(  # type:ignore
                    container=container, active_endpoints=loki_endpoints, topology=self._topology
                )

    def disable_logging(self, _: Optional[ops.EventBase] = None):
        """Disable all log forwarding."""
        # This is currently necessary because, after a relation broken, the charm can still see
        # the Loki endpoints in the relation data.
        for container in self._charm.unit.containers.values():
            if container.can_connect():
                _PebbleLogClient.disable_inactive_endpoints(  # type:ignore
                    container=container, active_endpoints={}, topology=self._topology
                )
