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
"""

import copy
import re
from pathlib import Path
from typing import Dict, Final, List, Literal, Optional

import cos_tool
import yaml
from cosl import JujuTopology
from pydantic import BaseModel, Field


class Rule(dict):
    """Dict subclass for rules, adding some utility methods."""

    @property
    def rule_type(self) -> Literal["alert", "record"]:
        """Whether the rule is an Alert or a Recording rule."""
        if "alert" in self:
            return "alert"
        if "record" in self:
            return "record"
        return "alert"

    @property
    def juju_topology(self) -> Optional[JujuTopology]:
        """Return the JujuTopology from the labels, if present."""
        if "labels" not in self:
            return None

        labels = self["labels"]
        model_uuid = labels.get("juju_model_uuid")
        model = labels.get("juju_model")
        application = labels.get("juju_application")
        unit = labels.get("juju_unit", "")
        charm = labels.get("juju_charm", "")
        if not model_uuid or not model or not application:
            return None

        return JujuTopology(
            model_uuid=model_uuid,
            model=model,
            application=application,
            unit=unit,
            charm_name=charm,
        )

    @staticmethod
    def inject_topology_labels_into_expr(
        rule: "Rule", query_type: Literal["promql", "logql"] = "promql"
    ) -> "Rule":
        """Inject the existing topology labels into the rule expression.

        Topology labels must already exist in the 'labels' section of the rule.
        """
        if "labels" not in rule:
            return rule

        new_rule: Rule = copy.deepcopy(rule)
        target_labels = {
            "juju_model",
            "juju_model_uuid",
            "juju_application",
            "juju_charm",
            "juju_unit",
        }
        labels: Dict[str, str] = {
            label: value
            for label, value in new_rule["labels"].items()
            if label in target_labels
        }
        tool = cos_tool.CosTool()
        new_rule["expr"] = tool.inject_label_matchers(
            expression=rule["expr"],
            topology=labels,
            expression_type=query_type,
        )
        return new_rule


class RuleGroup(BaseModel):
    """Group a set of rules."""

    name: str = Field(description="Name of the rule group")
    rules: List[Rule] = Field(description="Rules that are part of the group")

    @property
    def prometheus_format(self) -> Dict:
        """Return the rule in Prometheus format, ready to be dropped into a file."""
        return {"groups": self.name, "rules": self.rules}

    @classmethod
    def from_dict(
        cls,
        raw_group: Dict,
        name_prefix: str,
        topology: JujuTopology,
        query_type: Literal["promql", "logql"] = "promql",
        extra_labels: Dict[str, str] = {},
    ) -> "RuleGroup":
        # NOTE: In the charm library we also add '_{rule_type}' for alerts/recording
        # Technically a group can have both
        group_name: str = f"{name_prefix}_{raw_group['name']}"
        # Sanitize the group name according to https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels
        group_name = "".join(
            char if re.match(r"[a-zA-Z0-9_:]", char) else "_" for char in group_name
        )
        for rule in raw_group["rules"]:
            # Add topology labels without overwriting them if they exist
            labels: Dict = rule.setdefault("labels", {})
            for label, value in topology.label_matcher_dict.items():
                if label not in labels:
                    labels[label] = value
            # Add extra_labels to the rule
            labels.update(extra_labels)
            rule["labels"] = labels
            # Add topology filters into the expression
            tool = cos_tool.CosTool()
            repl = r'job=~".+"' if query_type == "logql" else ""
            rule["expr"] = tool.inject_label_matchers(
                expression=re.sub(r"%%juju_topology%%,?", repl, rule["expr"]),
                topology={
                    k: rule["labels"][k]
                    for k in ("juju_model", "juju_model_uuid", "juju_application")
                    if rule["labels"].get(k) is not None
                },
                expression_type=query_type,
            )

        return cls(name=group_name, rules=raw_group["rules"])

    @classmethod
    def from_file(
        cls,
        path: Path,
        name_prefix: str,
        topology: JujuTopology,
        query_type: Literal["promql", "logql"] = "promql",
        extra_labels: Dict[str, str] = {},
    ) -> List["RuleGroup"]:
        if not path.is_file():
            raise ValueError(f"Path {path} is not a file")

        # Read the file into a dictionary
        try:
            with path.open() as p:
                raw_groups = yaml.safe_load(p)
        except Exception as e:
            logger.error(f"Failed to read rules from file {path}: {e}")
            return []

        file_groups: List["RuleGroup"] = []
        # NOTE: This explicitly drops support for single-file alert rules
        for raw_group in raw_groups["groups"]:
            file_groups.append(
                RuleGroup.from_dict(
                    raw_group=raw_group,
                    name_prefix=name_prefix,
                    topology=topology,
                    query_type=query_type,
                    extra_labels=extra_labels,
                )
            )

        return file_groups

    @classmethod
    def from_folder(
        cls,
        path: Path,
        topology: JujuTopology,
        recursive: bool = False,
        query_type: Literal["promql", "logql"] = "promql",
        extra_labels: Dict[str, str] = {},
    ) -> List["RuleGroup"]:
        if not path.is_dir():
            raise ValueError(f"Path {path} is not a directory")

        folder_groups: List["RuleGroup"] = []
        # Only parse files with the *allowed* suffixes
        for file in path.glob("**/*" if recursive else "*"):
            if not file.is_file() or file.suffix not in [
                ".rule",
                ".rules",
                ".yml",
                ".yaml",
            ]:
                continue

            # Build the group name from the juju_topology identifier and relative file path
            group_name_prefix = f"{topology.identifier}"
            if relative_path := file.parent.relative_to(path) != Path("."):
                group_name_prefix = f"{topology.identifier}_{relative_path}"
            groups = cls.from_file(
                path=file,
                name_prefix=group_name_prefix,
                topology=topology,
                query_type=query_type,
                extra_labels=extra_labels,
            )
            folder_groups.extend(groups)

        return folder_groups


class GenericRules(BaseModel):
    topology: JujuTopology
    extra_labels: Dict[str, str] = {}

    _rule_host_down: Final[Dict] = {
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
    }

    _rule_host_metrics_missing: Final[Dict] = {
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
    }

    @property
    def metrics_provider_alerts(self) -> RuleGroup:
        """Generic alert rules for metrics providers."""
        return RuleGroup.from_dict(
            raw_group={
                "groups": [
                    {
                        "name": "HostHealth",
                        "rules": [
                            self._rule_host_down,
                            self._rule_host_metrics_missing,
                        ],
                    }
                ]
            },
            name_prefix=self.topology.identifier,
            topology=self.topology,
            extra_labels=self.extra_labels,
        )

    @property
    def metrics_aggregator_alerts(self) -> RuleGroup:
        """Generic alert rules for metrics aggregators like OpenTelemetry Collector."""
        return RuleGroup.from_dict(
            raw_group={
                "groups": [
                    {
                        "name": "AggregatorHostHealth",
                        "rules": [self._rule_host_metrics_missing],
                    }
                ]
            },
            name_prefix=self.topology.identifier,
            topology=self.topology,
            extra_labels=self.extra_labels,
        )
