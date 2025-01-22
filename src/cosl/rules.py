# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""Alerting and Recording Rules.

## Overview

## Rules

This library also supports gathering alerting and recording rules from all
related charms and enabling corresponding alerting/recording rules within the
Prometheus charm.  Alert rules are automatically gathered by `AlertRules`
charms when using this library, from a directory conventionally named as one of:
- `prometheus_alert_rules`
- `prometheus_recording_rules`
- `loki_alert_rules`
- `loki_recording_rules`

This directory must reside at the top level in the `src` folder of the consumer
charm. Each file in this directory is assumed to be in one of two formats:
- the official Prometheus rule format, conforming to the
[Prometheus docs](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
- a single rule format, which is a simplified subset of the official format,
comprising a single alert rule per file, using the same YAML fields.

The file name must have one of the following extensions:
- `.rule`
- `.rules`
- `.yml`
- `.yaml`

An example of the contents of such a file in the custom single rule
format is shown below.

```
alert: HighRequestLatency
expr: job:request_latency_seconds:mean5m{my_key=my_value} > 0.5
for: 10m
labels:
  severity: Medium
  type: HighLatency
annotations:
  summary: High request latency for {{ $labels.instance }}.
```

The `[Alert|Recording]Rules` instance will read all available rules and
also inject "filtering labels" into the expressions. The
filtering labels ensure that rules are localised to the metrics
provider charm's Juju topology (application, model and its UUID). Such
a topology filter is essential to ensure that rules submitted by
one provider charm generates information only for that same charm. When
rules are embedded in a charm, and the charm is deployed as a
Juju application, the rules from that application have their
expressions automatically updated to filter for metrics/logs coming from
the units of that application alone. This removes risk of spurious
evaluation, e.g., when you have multiple deployments of the same charm
monitored by the same Prometheus or Loki.

Not all rules one may want to specify can be embedded in a
charm. Some rules will be specific to a user's use case. This is
the case, for example, of rules that are based on business
constraints, like expecting a certain amount of requests to a specific
API every five minutes. Such alerting or recording rules can be specified
via the [COS Config Charm](https://charmhub.io/cos-configuration-k8s),
which allows importing alert rules and other settings like dashboards
from a Git repository.

Gathering rules and generating rule files within a
charm is easily done using the `alerts()` or `recording_rules()` method(s)
of the consuming charm. Rules generated will automatically include Juju
topology labels. These labels indicate the source of the record or alert.
The following labels are automatically included with each rule:

- `juju_model`
- `juju_model_uuid`
- `juju_application`
"""  # noqa: W505

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Final, List, Optional, Union, cast

import yaml

from . import CosTool, JujuTopology
from .types import (
    OfficialRuleFileItem,
    QueryType,
    RuleType,
)

logger = logging.getLogger(__name__)


_generic_alert_rules: Final = SimpleNamespace(
    # We use "5m" to avoid false positives on expected temporary "down", e.g. during intentional (re)start.
    # Juju topology will be later injected by providers of alert rules.
    host_down={
        "alert": "HostDown",
        "expr": "up < 1",
        "for": "5m",
        "labels": {"severity": "critical"},
        "annotations": {
            "summary": "Host '{{ $labels.instance }}' is down.",
            "description": """Host '{{ $labels.instance }}' is down, failed to scrape.
                            VALUE = {{ $value }}
                            LABELS = {{ $labels }}""",
        },
    },
    host_metrics_missing={
        "alert": "HostMetricsMissing",
        # We use "absent(up)" with "for: 5m" because the alert transitions from "Pending" to "Firing".
        # If query portability is desired, "absent_over_time(up[5m])" is an alternative.
        "expr": "absent(up)",
        "for": "5m",
        "labels": {"severity": "critical"},
        "annotations": {
            "summary": "Metrics not received from host '{{ $labels.instance }}', failed to remote write.",
            "description": """Metrics not received from host '{{ $labels.instance }}', failed to remote write.
                            VALUE = {{ $value }}
                            LABELS = {{ $labels }}""",
        },
    },
)

"""
Generic alert rules are in groups to ensure a predictable group name.
"""
generic_alert_groups: Final = SimpleNamespace(
    # Group names must be unique per alert rule file. The final group names may be adjusted by the
    # providers of alert rules to include some topology information, to addresses deduplication.
    application_rules={
        "groups": [
            {
                "name": "HostHealth",
                "rules": [
                    _generic_alert_rules.host_down,
                    _generic_alert_rules.host_metrics_missing,
                ],
            },
        ]
    },
    # If we push to Prometheus via remote-write with an aggregator, there are no UP metrics associated.
    # Only a time series for the metrics we have pushed is available so omit the HostDown rule.
    aggregator_rules={
        "groups": [
            {
                "name": "AggregatorHostHealth",
                "rules": [
                    _generic_alert_rules.host_metrics_missing,
                ],
            },
        ]
    },
)


class InvalidRulePathError(Exception):
    """Raised if the rules folder cannot be found or is otherwise invalid."""

    def __init__(
        self,
        rules_absolute_path: Path,
        message: str,
    ):
        self.rules_absolute_path = rules_absolute_path
        self.message = message

        super().__init__(self.message)


class Rules(ABC):
    """Utility class for amalgamating alerting/recording rule  files and injecting juju topology.

    A `Rules` object supports aggregating rules from files and directories in both
    official and single rule file formats using the `add_path()` method. All the rules
    read are annotated with Juju topology labels and amalgamated into a single data structure
    in the form of a Python dictionary using the `as_dict()` method. Such a dictionary can be
    easily dumped into JSON format and exchanged over relation data. The dictionary can also
    be dumped into YAML format and written directly into a rules file that is read by
    Prometheus. Note that multiple `Rules` objects must not be written into the same file,
    since Prometheus allows only a single list of rule groups per rules file.

    The official  format is a YAML file conforming to the Prometheus/Cortex documentation
    (https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/).
    The custom single rule format is a subsection of the official YAML, having a single alert
    rule, effectively "one alert per file".
    """

    # This class uses the following terminology for the various parts of a rule file:
    # - rules file: the entire groups[] yaml, including the "groups:" key.
    # - groups (plural): the list of groups[] (a list, i.e. no "groups:" key) - it is a list
    #   of dictionaries that have the "name" and "rules" keys.
    # - group (singular): a single dictionary that has the "name" and "rules" keys.
    # - rules (plural): all the rules in a given group - a list of dictionaries with
    #   the `self.rule_type` (either "alert" or "record") and "expr" keys.
    # - rule (singular): a single dictionary that has the `self.rule_type` (either "alert" or
    #   "record") and "expr" keys.

    def __init__(self, query_type: QueryType, topology: Optional[JujuTopology] = None):
        """Build a rule object.

        Args:
            query_type: either "promql" or "logql" to indicate the query language used
                in the rules, for manipulation with CosTool
            topology: an optional `JujuTopology` instance that is used to annotate all rules.
        """
        self.query_type = query_type
        self.topology = topology
        self.tool = CosTool(default_query_type=query_type)
        self.groups: List[OfficialRuleFileItem] = []

    @property
    @abstractmethod
    def rule_type(self) -> RuleType:
        """Return the rule type being used for interpolation in messages."""
        pass

    # --- HELPER METHODS FOR READING FILES, SHOULD BE STATIC --- #

    @staticmethod
    def _is_official_rule_format(rules_dict: Dict[str, Any]) -> bool:
        """Are rules in the upstream format as supported by Prometheus or Loki.

        Rules in dictionary format are in "official" form if they
        contain a "groups" key, since this implies they contain a list of
        rule groups.

        Args:
            rules_dict: a set of rules in Python dictionary format

        Returns:
            True if rules are in official file format.
        """
        return "groups" in rules_dict

    @staticmethod
    def _is_single_rule_format(rules_dict: Dict[str, Any], rule_type: RuleType) -> bool:
        """Are alert rules in single rule format.

        This library supports reading of rules in a custom format that
        consists of a single rule per file. This does not conform to the
        official rule file format, which requires that each rules file
        consists of a list of rule groups and each group consists of a
        list of rules.

        Rules in dictionary form are considered to be in single rule
        format if in the least it contains two keys corresponding to the
        rule name and expression.

        Returns:
            True if rule is in single rule file format.
        """
        # one rule per file
        return set(rules_dict) >= {rule_type, "expr"}

    @staticmethod
    def _multi_suffix_glob(
        dir_path: Path, suffixes: List[str], recursive: bool = True
    ) -> List[Path]:
        """Helper function for getting all files in a directory that have a matching suffix.

        Args:
            dir_path: path to the directory to glob from.
            suffixes: list of suffixes to include in the glob (items should begin with a period).
            recursive: a flag indicating whether a glob is recursive (nested) or not.

        Returns:
            List of files in `dir_path` that have one of the suffixes specified in `suffixes`.
        """
        all_files_in_dir = dir_path.glob("**/*" if recursive else "*")
        return list(filter(lambda f: f.is_file() and f.suffix in suffixes, all_files_in_dir))

    def _from_dir(self, dir_path: Path, recursive: bool) -> List[OfficialRuleFileItem]:
        """Read all rule files in a directory.

        All rules from files for the same directory are loaded into a single
        group. The generated name of this group includes juju topology.
        By default, only the top directory is scanned; for nested scanning, pass `recursive=True`.

        Args:
            dir_path: directory containing *.rule files (rules without groups).
            recursive: flag indicating whether to scan for rule files recursively.

        Returns:
            a list of dictionaries representing prometheus rule groups, each dictionary
            representing a group (structure determined by `yaml.safe_load`).
        """
        groups: List[OfficialRuleFileItem] = []

        # Gather all records into a list of groups
        for file_path in Rules._multi_suffix_glob(
            dir_path, [".rule", ".rules", ".yml", ".yaml"], recursive
        ):
            groups_from_file = self._from_file(dir_path, file_path)
            if groups_from_file:
                logger.debug("Reading %s rule from %s", self.rule_type, file_path)
                groups.extend(groups_from_file)  # type: ignore

        return groups

    def _from_file(  # noqa: C901
        self, root_path: Path, file_path: Path
    ) -> List[OfficialRuleFileItem]:
        """Read a rules file from path.

        Args:
            root_path: full path to the root rules folder (used only for generating group name)
            file_path: full path to a *.rule file.

        Returns:
            A list of dictionaries representing the rules file, if file is valid (the structure is
            formed by `yaml.safe_load` of the file); an empty list otherwise.
        """
        with file_path.open() as rf:
            # Load a list of rules from file then add labels and filters
            try:
                rule_file = yaml.safe_load(rf)

            except Exception as e:
                logger.error("Failed to read rules from %s: %s", file_path.name, e)
                return []

            # Generate group name prefix
            #  - name, from juju topology
            #  - suffix, from the relative path of the rule file;
            rel_path = file_path.parent.relative_to(root_path)
            rel_path = "" if rel_path == Path(".") else str(rel_path)
            group_name_parts = [self.topology.identifier] if self.topology else []
            group_name_parts.append(rel_path)
            group_name_prefix = "_".join(filter(None, group_name_parts))

            try:
                groups = self._from_dict(
                    rule_file, group_name=file_path.stem, group_name_prefix=group_name_prefix
                )
            except ValueError as e:
                logger.error("Invalid rules file: %s (%s)", file_path.name, e)
                return []

            return groups

    def _from_dict(
        self,
        rule_dict: Dict[str, Any],
        *,
        group_name: Optional[str] = None,
        group_name_prefix: Optional[str] = None,
    ) -> List[OfficialRuleFileItem]:
        """Process rules from dict, injecting juju topology. If a single-rule format is provided, a hash of the yaml file is injected into the group name to ensure uniqueness.

        Args:
            rule_dict: rules content in single-rule or official-rule format as a YAML dict
            group_name: a custom identifier for the rule name to include in the group name
            group_name_prefix: a custom group identifier to prefix the resulting group name, likely Juju topology and relative path context

        Raises:
            ValueError, when invalid rule format given.
        """
        if not rule_dict:
            raise ValueError("Empty")

        if self._is_official_rule_format(rule_dict):
            groups = rule_dict["groups"]
        elif self._is_single_rule_format(rule_dict, self.rule_type):
            if not group_name:
                # Note: the caller of this function should ensure this never happens:
                # Either we use the standard format, or we'd pass a group_name.
                # If/when we drop support for the single-rule-per-file format, this won't
                # be needed anymore.
                group_name = hashlib.shake_256(str(rule_dict).encode("utf-8")).hexdigest(10)

            # convert to list of groups to match official rule format
            groups = [{"name": group_name, "rules": [rule_dict]}]
        else:
            # invalid/unsupported
            raise ValueError("Invalid rule format")

        # update rules with additional metadata
        groups = cast(List[OfficialRuleFileItem], groups)
        for group in groups:
            if not self._is_already_modified(group["name"]):
                # update group name with topology and sub-path
                group["name"] = "_".join(
                    filter(None, [group_name_prefix, group["name"], f"{self.rule_type}s"])
                )
            # after sanitizing we should not modify group["name"] anymore
            group["name"] = self._sanitize_metric_name(group["name"])

            # add "juju_" topology labels
            for rule in group["rules"]:
                if "labels" not in rule:
                    rule["labels"] = {}

                if self.topology:
                    # only insert labels that do not already exist
                    for label, val in self.topology.label_matcher_dict.items():
                        if label not in rule["labels"]:
                            rule["labels"][label] = val

                    # insert juju topology filters into a prometheus rule
                    repl = r'job=~".+"' if self.query_type == "logql" else ""
                    rule["expr"] = self.tool.inject_label_matchers(  # type: ignore
                        expression=re.sub(r"%%juju_topology%%,?", repl, rule["expr"]),
                        topology={
                            k: rule["labels"][k]
                            for k in ("juju_model", "juju_model_uuid", "juju_application")
                            if rule["labels"].get(k) is not None
                        },
                        query_type=self.query_type,
                    )

        return groups

    def _is_already_modified(self, name: str) -> bool:
        """Detect whether a group name has already been modified with juju topology."""
        modified_matcher = re.compile(r"^.*?_[\da-f]{8}_.*?alerts$")
        if modified_matcher.match(name) is None:
            return False
        return True

    def _sanitize_metric_name(self, metric_name: str) -> str:
        """Sanitize a metric name according to https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels."""
        return "".join(char if re.match(r"[a-zA-Z0-9_:]", char) else "_" for char in metric_name)

    # ---- END STATIC HELPER METHODS --- #

    def add(
        self,
        rule_dict: Dict[str, Any],
        group_name: Optional[str] = None,
        group_name_prefix: Optional[str] = None,
    ) -> None:
        """Add rules from dict to the existing ruleset.

        Args:
            rule_dict: a single-rule or official-rule YAML dict
            group_name: a custom group name, used only if the new rule is of single-rule format
            group_name_prefix: a custom group name prefix, used only if the new rule is of single-rule format
        """
        self.groups.extend(
            self._from_dict(rule_dict, group_name=group_name, group_name_prefix=group_name_prefix)
        )

    def add_path(self, dir_path: Union[str, Path], *, recursive: bool = False) -> None:
        """Add rules from a dir path.

        All rules from files are aggregated into a data structure representing a single rule file.
        All group names are augmented with juju topology.

        Args:
            dir_path: either a rules file or a dir of rules files.
            recursive: whether to read files recursively or not (no impact if `path` is a file).
        """
        path = Path(dir_path) if isinstance(dir_path, str) else dir_path
        if path.is_dir():
            self.groups.extend(self._from_dir(path, recursive))
        elif path.is_file():
            self.groups.extend(self._from_file(path.parent, path))  # type: ignore
        else:
            logger.debug("%s rules path does not exist: %s", self.rule_type.capitalize(), path)

    def as_dict(self) -> Dict[str, Any]:
        """Return standard rules file in dict representation.

        Returns:
            a dictionary containing a single list of rule groups.
            The list of rule groups is provided as value of the
            "groups" dictionary key.
        """
        return {"groups": self.groups} if self.groups else {}


class AlertRules(Rules):
    """Utility class for amalgamating alerting files and injecting juju topology.

    The official format is a YAML file conforming to the Prometheus/Cortex documentation
    (https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/).
    The custom single rule format is a subsection of the official YAML, having a single alert
    rule, effectively "one alert per file".
    """

    _rule_type = "alert"  # type: RuleType

    @property
    def rule_type(self) -> RuleType:
        """Return the rule type being used for interpolation in messages."""
        return self._rule_type


class RecordingRules(Rules):
    """Utility class for amalgamating recording files and injecting juju topology.

    The official format is a YAML file conforming to the Prometheus/Cortex documentation
    (https://prometheus.io/docs/prometheus/latest/configuration/recording_rules/).
    The custom single rule format is a subsection of the official YAML, having a single recording
    rule, effectively "one record per file".
    """

    _rule_type = "record"  # type: RuleType

    @property
    def rule_type(self) -> RuleType:
        """Return the rule type being used for interpolation in messages."""
        return self._rule_type
