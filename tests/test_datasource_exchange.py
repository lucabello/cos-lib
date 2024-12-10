import json

import pytest
from ops import CharmBase, Framework
from scenario import Context, Relation, State
from scenario.errors import UncaughtCharmError

from cosl.interfaces.datasource_exchange import (
    DatasourceExchange,
    DSExchangeAppData,
    EndpointValidationError,
    GrafanaDatasource,
)


@pytest.mark.parametrize(
    "meta, declared",
    (
        (
            {},
            (None, None),
        ),
        (
            {
                "requires": {"boo": {"interface": "gibberish"}},
                "provides": {"far": {"interface": "grafana_datasource_exchange"}},
            },
            ("far", "boo"),
        ),
        (
            {
                "requires": {"boo": {"interface": "grafana_datasource_exchange"}},
                "provides": {"goo": {"interface": "grafana_datasource_exchange"}},
            },
            ("far", "boo"),
        ),
    ),
)
def test_endpoint_validation_failure(meta, declared):
    # GIVEN a charm with this metadata and declared provider/requirer endpoints

    class BadCharm(CharmBase):
        def __init__(self, framework: Framework):
            super().__init__(framework)
            prov, req = declared
            self.ds_exchange = DatasourceExchange(
                self, provider_endpoint=prov, requirer_endpoint=req
            )

    # WHEN any event is processed
    with pytest.raises(UncaughtCharmError) as e:
        ctx = Context(BadCharm, meta={"name": "bob", **meta})
        ctx.run(ctx.on.update_status(), State())

    # THEN we raise an EndpointValidationError
    assert isinstance(e.value.__cause__, EndpointValidationError)


@pytest.mark.parametrize(
    "meta, declared",
    (
        (
            {
                "requires": {"boo": {"interface": "grafana_datasource_exchange"}},
                "provides": {"far": {"interface": "grafana_datasource_exchange"}},
            },
            ("far", "boo"),
        ),
        (
            {
                "provides": {"far": {"interface": "grafana_datasource_exchange"}},
            },
            ("far", None),
        ),
        (
            {
                "requires": {"boo": {"interface": "grafana_datasource_exchange"}},
            },
            (None, "boo"),
        ),
    ),
)
def test_endpoint_validation_ok(meta, declared):
    # GIVEN a charm with this metadata and declared provider/requirer endpoints
    class BadCharm(CharmBase):
        def __init__(self, framework: Framework):
            super().__init__(framework)
            prov, req = declared
            self.ds_exchange = DatasourceExchange(
                self, provider_endpoint=prov, requirer_endpoint=req
            )

    # WHEN any event is processed
    ctx = Context(BadCharm, meta={"name": "bob", **meta})
    ctx.run(ctx.on.update_status(), State())
    # THEN no exception is raised


def test_ds_publish():
    # GIVEN a charm with a single datasource_exchange relation
    class MyCharm(CharmBase):
        META = {
            "name": "robbie",
            "provides": {"foo": {"interface": "grafana_datasource_exchange"}},
        }

        def __init__(self, framework: Framework):
            super().__init__(framework)
            self.ds_exchange = DatasourceExchange(
                self, provider_endpoint="foo", requirer_endpoint=None
            )
            self.ds_exchange.publish([{"type": "tempo", "uid": "123", "grafana_uid": "123123"}])

    ctx = Context(MyCharm, meta=MyCharm.META)

    dse_in = Relation("foo")
    state_in = State(relations={dse_in}, leader=True)

    # WHEN we receive any event
    state_out = ctx.run(ctx.on.update_status(), state_in)

    # THEN we publish in our app databags any datasources we're aware of
    dse_out = state_out.get_relation(dse_in.id)
    assert dse_out.local_app_data
    data = DSExchangeAppData.load(dse_out.local_app_data)
    assert data.datasources[0].type == "tempo"
    assert data.datasources[0].uid == "123"


def test_ds_receive():
    # GIVEN a charm with a single datasource_exchange relation
    class MyCharm(CharmBase):
        META = {
            "name": "robbie",
            "provides": {"foo": {"interface": "grafana_datasource_exchange"}},
            "requires": {"bar": {"interface": "grafana_datasource_exchange"}},
        }

        def __init__(self, framework: Framework):
            super().__init__(framework)
            self.ds_exchange = DatasourceExchange(
                self, provider_endpoint="foo", requirer_endpoint="bar"
            )

    ctx = Context(MyCharm, meta=MyCharm.META)

    ds_requirer_in = [
        {"type": "c", "uid": "3", "grafana_uid": "4"},
        {"type": "a", "uid": "1", "grafana_uid": "5"},
        {"type": "b", "uid": "2", "grafana_uid": "6"},
    ]
    ds_provider_in = [{"type": "d", "uid": "4", "grafana_uid": "7"}]

    dse_requirer_in = Relation(
        "foo",
        remote_app_data=DSExchangeAppData(
            datasources=json.dumps(sorted(ds_provider_in, key=lambda raw_ds: raw_ds["uid"]))
        ).dump(),
    )
    dse_provider_in = Relation(
        "bar",
        remote_app_data=DSExchangeAppData(
            datasources=json.dumps(sorted(ds_requirer_in, key=lambda raw_ds: raw_ds["uid"]))
        ).dump(),
    )
    state_in = State(relations={dse_requirer_in, dse_provider_in}, leader=True)

    # WHEN we receive any event
    with ctx(ctx.on.update_status(), state_in) as mgr:
        # THEN we can access all datasources we're given
        dss = mgr.charm.ds_exchange.received_datasources
        assert [ds.type for ds in dss] == list("abcd")
        assert [ds.uid for ds in dss] == list("1234")
        assert isinstance(dss[0], GrafanaDatasource)
