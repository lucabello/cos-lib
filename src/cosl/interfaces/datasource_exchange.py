#!/usr/bin/env python3
# Copyright 2024 Canonical
# See LICENSE file for licensing details.

"""Shared utilities for the inter-coordinator "grafana_datasource_exchange" interface.

See https://github.com/canonical/charm-relation-interfaces/tree/main/interfaces/grafana_datasource_exchange/v0
for the interface specification.
"""

# FIXME: the interfaces import (because it's a git dep perhaps?)
#  can't be type-checked, which breaks everything
# pyright: reportMissingImports=false
# pyright: reportUntypedBaseClass=false
# pyright: reportUnknownLambdaType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownParameterType=false


import json
import logging
from typing import (
    Iterable,
    List,
    Optional,
    Tuple,
)

import ops
from ops import CharmBase
from pydantic import BaseModel, Field, Json
from typing_extensions import TypedDict

import cosl.interfaces.utils
from cosl.interfaces.utils import DataValidationError

log = logging.getLogger("datasource_exchange")

DS_EXCHANGE_INTERFACE_NAME = "grafana_datasource_exchange"


# FIXME copy-pasta'd from charm-relation-interfaces. Keep in sync!
#  see https://github.com/canonical/charm-relation-interfaces/issues/213
class GrafanaDatasource(BaseModel):
    """GrafanaDatasource model."""

    type: str = Field(
        description="Type of the datasource, typically one of "
        "https://grafana.com/docs/grafana/latest/datasources/#built-in-core-data-sources.",
        examples=["tempo", "loki", "prometheus", "elasticsearch"],
    )
    uid: str = Field(description="Grafana datasource UID, as assigned by Grafana.")
    grafana_uid: str = Field(description="Grafana UID.")


class GrafanaSourceAppData(BaseModel):
    """Application databag model for both sides of this interface."""

    datasources: Json[List[GrafanaDatasource]]


class DSExchangeAppData(cosl.interfaces.utils.DatabagModelV2, GrafanaSourceAppData):
    """App databag schema for both sides of this interface."""


class DatasourceDict(TypedDict):
    """Raw datasource information."""

    type: str
    uid: str
    grafana_uid: str


class EndpointValidationError(ValueError):
    """Raised if an endpoint name is invalid."""


def _validate_endpoints(
    charm: CharmBase, provider_endpoint: Optional[str], requirer_endpoint: Optional[str]
):
    meta = charm.meta
    for endpoint, source in (
        (provider_endpoint, meta.provides),
        (requirer_endpoint, meta.requires),
    ):
        if endpoint is None:
            continue
        if endpoint not in source:
            raise EndpointValidationError(f"endpoint {endpoint!r} not declared in charm metadata")
        interface_name = source[endpoint].interface_name
        if interface_name != DS_EXCHANGE_INTERFACE_NAME:
            raise EndpointValidationError(
                f"endpoint {endpoint} has unexpected interface {interface_name!r} "
                f"(should be {DS_EXCHANGE_INTERFACE_NAME})."
            )
    if not provider_endpoint and not requirer_endpoint:
        raise EndpointValidationError(
            "This charm should implement either a requirer or a provider (or both)"
            "endpoint for `grafana-datasource-exchange`."
        )


class DatasourceExchange:
    """``grafana_datasource_exchange`` interface endpoint wrapper (provider AND requirer)."""

    def __init__(
        self,
        charm: ops.CharmBase,
        *,
        provider_endpoint: Optional[str],
        requirer_endpoint: Optional[str],
    ):
        self._charm = charm
        _validate_endpoints(charm, provider_endpoint, requirer_endpoint)

        # gather all relations, provider or requirer
        all_relations = []
        if provider_endpoint:
            all_relations.extend(charm.model.relations.get(provider_endpoint, ()))
        if requirer_endpoint:
            all_relations.extend(charm.model.relations.get(requirer_endpoint, ()))

        # filter out some common unhappy relation states
        self._relations: List[ops.Relation] = [
            rel for rel in all_relations if (rel.app and rel.data)
        ]

    def publish(self, datasources: Iterable[DatasourceDict]):
        """Submit these datasources to all remotes.

        This operation is leader-only.
        """
        # sort by UID to prevent endless relation-changed cascades if this keeps flapping
        encoded_datasources = json.dumps(sorted(datasources, key=lambda raw_ds: raw_ds["uid"]))
        app_data = DSExchangeAppData(
            datasources=encoded_datasources  # type: ignore[reportCallIssue]
        )

        for relation in self._relations:
            app_data.dump(relation.data[self._charm.app])

    @property
    def received_datasources(self) -> Tuple[GrafanaDatasource, ...]:
        """Collect all datasources that the remotes have shared.

        This operation is leader-only.
        """
        datasources: List[GrafanaDatasource] = []

        for relation in self._relations:
            try:
                datasource = DSExchangeAppData.load(relation.data[relation.app])
            except DataValidationError:
                # load() already logs something in this case
                continue

            datasources.extend(datasource.datasources)
        return tuple(sorted(datasources, key=lambda ds: ds.uid))
