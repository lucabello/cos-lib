import itertools
from typing import Type

import ops

from cosl.reconciler import all_events, reconcilable_events_k8s, reconcilable_events_machine


def _get_inheritance_tree_leaves(cl: Type):
    return list(
        itertools.chain(
            *[
                (
                    [subc]
                    if (subc.__module__.startswith("ops.") and not subc.__subclasses__())
                    else _get_inheritance_tree_leaves(subc)
                )
                for subc in cl.__subclasses__()
            ]
        )
    )


EXCLUDED_EVENTS = {
    ops.CollectMetricsEvent,
}

EXCLUDED_EVENTS_K8S = EXCLUDED_EVENTS.union(
    {
        ops.PebbleCustomNoticeEvent,
        ops.RemoveEvent,
        ops.UpgradeCharmEvent,
    }
)

EXCLUDED_EVENTS_VM = EXCLUDED_EVENTS.union(
    {
        ops.InstallEvent,
        ops.RemoveEvent,
        ops.StartEvent,
        ops.StopEvent,
        ops.UpgradeCharmEvent,
    }
)


def test_correctness():
    """Verify we are surfacing only valid events."""
    all_event_types = set(_get_inheritance_tree_leaves(ops.EventBase))
    assert set(all_events).issubset(all_event_types)


def test_completeness():
    """Verify we are surfacing all events we care about.

    If a new version of ops adds more event types, this will start failing.
    Then we'll have to make a
    choice about whether to put those events in the safe or unsafe bucket.
    """
    all_event_types = set(_get_inheritance_tree_leaves(ops.HookEvent))
    assert set(all_events).union(EXCLUDED_EVENTS) == all_event_types
    assert set(reconcilable_events_k8s).union(EXCLUDED_EVENTS_K8S) == all_event_types
    assert set(reconcilable_events_machine).union(EXCLUDED_EVENTS_VM) == all_event_types


def test_exclusiveness():
    """Verify the safe and unsafe buckets have no intersection."""
    assert set(all_events).intersection(EXCLUDED_EVENTS) == set()
    assert set(reconcilable_events_k8s).intersection(EXCLUDED_EVENTS_K8S) == set()
    assert set(reconcilable_events_machine).intersection(EXCLUDED_EVENTS_VM) == set()
