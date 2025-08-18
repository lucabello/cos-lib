"""Regretful reconciler charm utils."""

import inspect
import itertools
from typing import Any, Callable, Final, Iterable, Set, Type, TypeVar, Union, cast

import ops

_EventTyp = TypeVar("_EventTyp", bound=Type[ops.EventBase])
_EventBaseSubclassIterable = Iterable[_EventTyp]
_EventBaseSubclassSet = Set[_EventTyp]

# baseline obtained by:
# all_events = _get_inheritance_tree_leaves(ops.HookEvent)
# where:
# def _get_inheritance_tree_leaves(cl:Type):
#     return list(
#         itertools.chain(
#             *[
#                 ([subc] if (subc.__module__.startswith("ops.") and not subc.__subclasses__()) else
#                 _get_inheritance_tree_leaves(subc)) for subc in cl.__subclasses__()
#             ]
#         )
#     )
# at: 11/8/2025 (ops==2.17.1)
all_events: Final[Set[Type[ops.EventBase]]] = {
    ops.charm.PebbleCheckRecoveredEvent,
    ops.charm.PebbleCheckFailedEvent,
    ops.charm.ConfigChangedEvent,
    ops.charm.UpdateStatusEvent,
    ops.charm.PreSeriesUpgradeEvent,
    ops.charm.PostSeriesUpgradeEvent,
    ops.charm.LeaderElectedEvent,
    ops.charm.LeaderSettingsChangedEvent,
    # ops.charm.CollectMetricsEvent,           # deprecated
    ops.charm.RelationCreatedEvent,
    ops.charm.PebbleReadyEvent,
    ops.charm.RelationJoinedEvent,
    ops.charm.RelationChangedEvent,
    ops.charm.RelationDepartedEvent,
    ops.charm.RelationBrokenEvent,
    ops.charm.StorageAttachedEvent,
    ops.charm.StorageDetachingEvent,
    ops.charm.SecretChangedEvent,
    ops.charm.SecretRotateEvent,
    ops.charm.SecretRemoveEvent,
    ops.charm.SecretExpiredEvent,
    ops.charm.InstallEvent,
    ops.charm.StartEvent,
    ops.charm.RemoveEvent,
    ops.charm.StopEvent,
    ops.charm.UpgradeCharmEvent,
    ops.charm.PebbleCustomNoticeEvent,
}

# reconcilable_events_k8s is a list of all_events EXCEPT those listed below.
# Always include a comment with the reason for exclusions
reconcilable_events_k8s: Final[Set[Type[ops.EventBase]]] = all_events.difference(
    {
        ops.charm.PebbleCustomNoticeEvent,  # sometimes you want to handle the various notices differently
        ops.charm.RemoveEvent,  # usually pointless and sometimes harmful to reconcile towards an up state if you're shutting down
        ops.charm.UpgradeCharmEvent,  # this is your only chance to know you've been upgraded
    }
)

# reconcilable_events_machine is a list of all_events EXCEPT those listed below.
# Always include a comment with the reason for exclusions
reconcilable_events_machine: Final[Set[Type[ops.EventBase]]] = all_events.difference(
    {
        ops.charm.InstallEvent,  # (machine) charms may want to observe this
        ops.charm.RemoveEvent,  # usually pointless and sometimes harmful to reconcile towards an up state if you're shutting down
        ops.charm.StartEvent,  # (machine) charms may want to observe this
        ops.charm.StopEvent,  # usually pointless and sometimes harmful to reconcile towards an up state if you're shutting down
        ops.charm.UpgradeCharmEvent,  # this is your only chance to know you've been upgraded
    }
)


_CTR = itertools.count()


def observe_events(
    charm: ops.CharmBase,
    events: Iterable[_EventTyp],
    handler: Union[Callable[[Any], None], Callable[[], None]],
):
    """Observe all events that are subtypes of a given list using the provided handler.

    Usage:
    >>> class MyCharm(ops.CharmBase):
    ...    def __init__(self, ...):
    ...        super().__init__(...)
    ...        observe_events(self, all_events, self.reconcile)
    ...
    ...     def reconcile(self):
    ...         pass

    Or:
    >>> class MyK8sCharm(ops.CharmBase):
    ...    def __init__(self, ...):
    ...        super().__init__(...)
    ...        observe_events(self, reconcilable_events_k8s, self._on_any_event)
    ...
    ...    def _on_any_event(self, _):
    ...        self.reconcile()
    ...
    ...     def reconcile(self):
    ...         pass

    Or:
    >>> class MyFineGrainedCharm(ops.CharmBase):
    ...    def __init__(self, ...):
    ...        super().__init__(...)
    ...        observe_events(self, {ops.StartEvent, ops.StopEvent}, self._on_group1)
    ...        observe_events(self, {ops.RelationEvent, ops.SecretEvent, ops.framework.LifecycleEvent}, self._on_group2,)
    ...        # ... add more groups as needed
    ...
    ...    def _on_group1(self):
    ...        pass
    ...
    ...     def _on_group2(self):
    ...        pass

    Or even! (but you're a bad person if you do this)
    >>> class MyCharm(ops.CharmBase):
    ...    def __init__(self, ...):
    ...        super().__init__(...)
    ...        observe_events(self, {ops.RelationEvent}, lambda: print("I am running a relation event"))
    """
    # ops types it with Any!
    evthandler: Callable[[Any], None]
    if not inspect.signature(handler).parameters:
        # handler provided is a function not part of an ops.Object
        class _Observer(ops.Object):
            _key = f"_observer_proxy_{next(_CTR)}"

            def __init__(self):
                super().__init__(charm, key=self._key)
                # attach ref to something solid to prevent inadvertently GC'ing this thang
                setattr(charm.framework, self._key, self)

            def evt_handler(self, _: ops.EventBase) -> None:
                handler()  # type: ignore

        evthandler = _Observer().evt_handler
    else:
        # handler provided is a method of an ops.Object
        evthandler = cast(Callable[[Any], None], handler)

    for bound_evt in charm.on.events().values():
        if any(issubclass(bound_evt.event_type, include_type) for include_type in events):
            charm.framework.observe(bound_evt, evthandler)
