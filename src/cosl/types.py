# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.
"""Types used by cos-lib."""
from typing import Dict, List, Literal, Optional, TypedDict, Union

from typing_extensions import Required

QueryType = Literal["logql", "promql"]
RuleType = Literal["alert", "record"]


class _RecordingRuleFormat(TypedDict):
    record: Required[str]
    expr: Required[str]
    labels: Dict[str, str]


class _AlertingRuleFormat(TypedDict):
    alert: Required[str]
    expr: Required[str]
    duration: Optional[str]
    keep_firing_for: Optional[str]
    labels: Dict[str, str]
    annotations: Optional[Dict[str, str]]


SingleRuleFormat = Union[_AlertingRuleFormat, _RecordingRuleFormat]


class OfficialRuleFileItem(TypedDict):
    """Typing for a single node of the official rule file format."""

    name: str
    rules: List[SingleRuleFormat]


class OfficialRuleFileFormat(TypedDict):
    """Typing for the official rule file format.

    References:
    - https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/
    - https://prometheus.io/docs/prometheus/latest/configuration/recording_rules/
    """

    groups: List[OfficialRuleFileItem]
