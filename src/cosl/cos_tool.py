# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""COS Tool."""

import logging
import platform
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import yaml
from typing_extensions import Concatenate, ParamSpec, TypeVar

from .types import OfficialRuleFileFormat, QueryType

logger = logging.getLogger(__name__)

_T = TypeVar("_T")
_P = ParamSpec("_P")


def ensure_querytype(func: Callable[_P, _T]) -> Callable[Concatenate["CosTool", _P], _T]:
    """A small decorator to ensure that query type is specified."""

    def wrapper(self: "CosTool", *args: _P.args, **kwargs: _P.kwargs) -> _T:
        if not self.query_type and not kwargs.get("query_type", None):
            raise TypeError(
                "Either a default query type or a per-method query type must be used for `CosTool`!"
            )
        return func(self, *args, **kwargs)  # type: ignore

    wrapper.__doc__ = func.__doc__
    return wrapper


class CosTool:
    """Uses cos-tool to inject label matchers into alert rule expressions and validate rules.

    Args:
        default_query_type: an optional querytype to use for all invocations of this class, if
          not specified per-method. Either :default_query_type: or per-method :query_type:
          **must** be used, or a :TypeError: will be raised.
    """

    _path = None
    _disabled = False
    query_type: Union[QueryType, None] = None

    def __init__(self, default_query_type: Optional[QueryType] = None):
        self.query_type = default_query_type

    @property
    def path(self):
        """Lazy lookup of the path of cos-tool."""
        if self._disabled:
            return None
        if not self._path:
            self._path = self._get_tool_path()
            if not self._path:
                logger.debug("Skipping injection of juju topology as label matchers")
                self._disabled = True
        return self._path

    @ensure_querytype
    def apply_label_matchers(
        self, rules: OfficialRuleFileFormat, query_type: Optional[QueryType] = None
    ) -> OfficialRuleFileFormat:
        """Will apply label matchers to the expression of all alerts in all supplied groups."""
        query_type = query_type or self.query_type
        if not self.path:
            return rules
        for group in rules["groups"]:
            rules_in_group = group.get("rules", [])
            for rule in rules_in_group:
                topology = {}
                # if the user for some reason has provided juju_unit, we'll need to honor it
                # in most cases, however, this will be empty
                for label in [
                    "juju_model",
                    "juju_model_uuid",
                    "juju_application",
                    "juju_charm",
                    "juju_unit",
                ]:
                    if label in rule["labels"]:
                        topology[label] = rule["labels"][label]

                rule["expr"] = self.inject_label_matchers(rule["expr"], topology, query_type)  # type: ignore
        return rules

    @ensure_querytype
    def validate_alert_rules(
        self, rules: Dict[str, Any], query_type: Optional[QueryType] = None
    ) -> Tuple[bool, str]:
        """Will validate correctness of alert rules, returning a boolean and any errors."""
        query_type = query_type or self.query_type
        if not self.path:
            logger.debug("`cos-tool` unavailable. Not validating alert correctness.")
            return True, ""

        with tempfile.TemporaryDirectory() as tmpdir:
            rule_path = Path(tmpdir + "/validate_rule.yaml")

            # Smash "our" rules format into what upstream actually uses for Loki,
            # which is more like:
            #
            # groups:
            #   - name: foo
            #     rules:
            #       - alert: SomeAlert
            #         expr: up
            #       - alert: OtherAlert
            #         expr: up
            if query_type == "logql":
                transformed_rules = {"groups": []}  # type: Dict[str, Any]
                for rule in rules["groups"]:
                    transformed = {"name": str(uuid.uuid4()), "rules": [rule]}
                    transformed_rules["groups"].append(transformed)

                rules = transformed_rules

            rule_path.write_text(yaml.dump(rules))

            args = [str(self.path), "--format", query_type, "validate", str(rule_path)]
            # noinspection PyBroadException
            try:
                self._exec(args)  # type: ignore
                return True, ""
            except subprocess.CalledProcessError as e:
                logger.debug("Validating the rules failed: %s", e.output.decode("utf-8"))
                return False, ", ".join(
                    [
                        line
                        for line in e.output.decode("utf-8").splitlines()
                        if "error validating" in line
                    ]
                )

    @ensure_querytype
    def inject_label_matchers(
        self,
        expression: str,
        topology: Dict[str, str],
        query_type: Optional[QueryType] = None,
        dashboard_variable: Optional[bool] = False,
    ) -> str:
        """Add label matchers to an expression."""
        query_type = query_type or self.query_type

        if not topology:
            return expression
        if not self.path:
            logger.debug("`cos-tool` unavailable. Leaving expression unchanged: %s", expression)
            return expression
        args = [str(self.path), "--format", query_type, "transform"]

        value_tmpl = r"${}" if dashboard_variable else "{}"

        variable_topology = {k: value_tmpl.format(topology[k]) for k in topology.keys()}
        args.extend(
            [
                "--label-matcher={}={}".format(key, value)
                for key, value in variable_topology.items()
            ]
        )

        # Pass a leading "--" so expressions with a negation or subtraction aren't interpreted as
        # flags
        args.extend(["--", "{}".format(expression)])
        # noinspection PyBroadException
        try:
            return (
                re.sub(r'="\$juju', r'=~"$juju', self._exec(args))  # type: ignore
                if dashboard_variable
                else self._exec(args)  # type: ignore
            )
        except subprocess.CalledProcessError as e:
            logger.debug('Applying the expression failed: "%s", falling back to the original', e)
            return expression

    def _get_tool_path(self) -> Optional[Path]:
        arch = platform.machine()
        arch = "amd64" if arch == "x86_64" else arch
        res = "cos-tool-{}".format(arch)
        try:
            path = Path(res).resolve()
            path.chmod(0o777)
            return path
        except NotImplementedError:
            logger.debug("System lacks support for chmod")
        except FileNotFoundError:
            logger.debug('Could not locate cos-tool at: "{}"'.format(res))
        return None

    def _exec(self, cmd: List[str]) -> str:
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return result.stdout.decode("utf-8").strip()
