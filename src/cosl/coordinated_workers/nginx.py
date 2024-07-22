# Copyright 2023 Canonical
# See LICENSE file for licensing details.

"""Workload manager for Nginx. Used by the coordinator to load-balance and group the workers."""

import logging
from typing import Callable, Optional, TypedDict

from ops import CharmBase, pebble

logger = logging.getLogger(__name__)

# TODO: should we add these to _NginxMapping and make them configurable / accessible?
NGINX_DIR = "/etc/nginx"
NGINX_CONFIG = f"{NGINX_DIR}/nginx.conf"
KEY_PATH = f"{NGINX_DIR}/certs/server.key"
CERT_PATH = f"{NGINX_DIR}/certs/server.cert"
CA_CERT_PATH = "/usr/local/share/ca-certificates/ca.cert"

_NginxMapping = TypedDict(
    "_NginxMapping", {"nginx_port": int, "nginx_exporter_port": int}, total=True
)
NginxMappingOverrides = TypedDict(
    "NginxMappingOverrides", {"nginx_port": int, "nginx_exporter_port": int}, total=False
)
DEFAULT_OPTIONS: _NginxMapping = {
    "nginx_port": 8080,
    "nginx_exporter_port": 9113,
}


class Nginx:
    """Helper class to manage the nginx workload."""

    config_path = NGINX_CONFIG
    _name = "nginx"
    options: _NginxMapping = DEFAULT_OPTIONS

    def __init__(
        self,
        charm: CharmBase,
        config_getter: Callable[[], str],
        options: Optional[NginxMappingOverrides] = None,
    ):
        self._charm = charm
        self._config_getter = config_getter
        self._container = self._charm.unit.get_container("nginx")
        self.options.update(options or {})

    @property
    def are_certificates_on_disk(self) -> bool:
        """Return True if the certificates files are on disk."""
        return (
            self._container.can_connect()
            and self._container.exists(CERT_PATH)
            and self._container.exists(KEY_PATH)
            and self._container.exists(CA_CERT_PATH)
        )

    def configure_tls(self, private_key: str, server_cert: str, ca_cert: str) -> None:
        """Save the certificates file to disk and run update-ca-certificates."""
        if self._container.can_connect():
            self._container.push(KEY_PATH, private_key, make_dirs=True)
            self._container.push(CERT_PATH, server_cert, make_dirs=True)
            self._container.push(CA_CERT_PATH, ca_cert, make_dirs=True)
            # FIXME: uncomment as soon as the nginx image contains the ca-certificates package
            # self._container.exec(["update-ca-certificates", "--fresh"])

    def delete_certificates(self) -> None:
        """Delete the certificate files from disk and run update-ca-certificates."""
        if self._container.can_connect():
            self._container.remove_path(CERT_PATH, recursive=True)
            self._container.remove_path(KEY_PATH, recursive=True)
            self._container.remove_path(CA_CERT_PATH, recursive=True)
            # FIXME: uncomment as soon as the nginx image contains the ca-certificates package
            # self._container.exec(["update-ca-certificates", "--fresh"])

    def _has_config_changed(self, new_config: str) -> bool:
        """Return True if the passed config differs from the one on disk."""
        if not self._container.can_connect():
            logger.debug("Could not connect to Nginx container")
            return False

        try:
            current_config = self._container.pull(self.config_path).read()
        except (pebble.ProtocolError, pebble.PathError) as e:
            logger.warning(
                "Could not check the current nginx configuration due to "
                "a failure in retrieving the file: %s",
                e,
            )
            return False

        return current_config != new_config

    def reload(self) -> None:
        """Reload the nginx config without restarting the service."""
        if self._container.can_connect():
            self._container.exec(["nginx", "-s", "reload"])

    def configure_pebble_layer(self) -> None:
        """Configure pebble layer."""
        if self._container.can_connect():
            new_config: str = self._config_getter()
            should_restart: bool = self._has_config_changed(new_config)
            self._container.push(self.config_path, new_config, make_dirs=True)  # type: ignore
            self._container.add_layer("nginx", self.layer, combine=True)
            self._container.autostart()

            if should_restart:
                logger.info("new nginx config: restarting the service")
                self.reload()

    @property
    def layer(self) -> pebble.Layer:
        """Return the Pebble layer for Nginx."""
        return pebble.Layer(
            {
                "summary": "nginx layer",
                "description": "pebble config layer for Nginx",
                "services": {
                    "nginx": {
                        "override": "replace",
                        "summary": "nginx",
                        "command": "nginx -g 'daemon off;'",
                        "startup": "enabled",
                    }
                },
            }
        )


class NginxPrometheusExporter:
    """Helper class to manage the nginx prometheus exporter workload."""

    options: _NginxMapping = DEFAULT_OPTIONS

    def __init__(self, charm: CharmBase, options: Optional[NginxMappingOverrides] = None) -> None:
        self._charm = charm
        self._container = self._charm.unit.get_container("nginx-prometheus-exporter")
        self.options.update(options or {})

    def configure_pebble_layer(self) -> None:
        """Configure pebble layer."""
        self._container.add_layer("nginx-prometheus-exporter", self.layer, combine=True)
        self._container.autostart()

    @property
    def layer(self) -> pebble.Layer:
        """Return the Pebble layer for Nginx Prometheus exporter."""
        scheme = "https" if self._charm.coordinator.tls_available else "http"  # type: ignore
        return pebble.Layer(
            {
                "summary": "nginx prometheus exporter layer",
                "description": "pebble config layer for Nginx Prometheus exporter",
                "services": {
                    "nginx": {
                        "override": "replace",
                        "summary": "nginx prometheus exporter",
                        "command": f"nginx-prometheus-exporter --no-nginx.ssl-verify --web.listen-address=:{self.options['nginx_exporter_port']}  --nginx.scrape-uri={scheme}://127.0.0.1:{self.options['nginx_port']}/status",
                        "startup": "enabled",
                    }
                },
            }
        )
