import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Callable, Dict, List, Literal, Optional

from cosl import DashboardPath40UID, LZMABase64

from cos_tool import CosTool

logger = logging.getLogger(__name__)

TOPOLOGY_TEMPLATE_DROPDOWNS = [  # type: ignore
    {
        "allValue": ".*",
        "datasource": "${prometheusds}",
        "definition": "label_values(up,juju_model)",
        "description": None,
        "error": None,
        "hide": 0,
        "includeAll": True,
        "label": "Juju model",
        "multi": True,
        "name": "juju_model",
        "query": {
            "query": "label_values(up,juju_model)",
            "refId": "StandardVariableQuery",
        },
        "refresh": 1,
        "regex": "",
        "skipUrlSync": False,
        "sort": 0,
        "tagValuesQuery": "",
        "tags": [],
        "tagsQuery": "",
        "type": "query",
        "useTags": False,
    },
    {
        "allValue": ".*",
        "datasource": "${prometheusds}",
        "definition": 'label_values(up{juju_model=~"$juju_model"},juju_model_uuid)',
        "description": None,
        "error": None,
        "hide": 0,
        "includeAll": True,
        "label": "Juju model uuid",
        "multi": True,
        "name": "juju_model_uuid",
        "query": {
            "query": 'label_values(up{juju_model=~"$juju_model"},juju_model_uuid)',
            "refId": "StandardVariableQuery",
        },
        "refresh": 1,
        "regex": "",
        "skipUrlSync": False,
        "sort": 0,
        "tagValuesQuery": "",
        "tags": [],
        "tagsQuery": "",
        "type": "query",
        "useTags": False,
    },
    {
        "allValue": ".*",
        "datasource": "${prometheusds}",
        "definition": 'label_values(up{juju_model=~"$juju_model",juju_model_uuid=~"$juju_model_uuid"},juju_application)',
        "description": None,
        "error": None,
        "hide": 0,
        "includeAll": True,
        "label": "Juju application",
        "multi": True,
        "name": "juju_application",
        "query": {
            "query": 'label_values(up{juju_model=~"$juju_model",juju_model_uuid=~"$juju_model_uuid"},juju_application)',
            "refId": "StandardVariableQuery",
        },
        "refresh": 1,
        "regex": "",
        "skipUrlSync": False,
        "sort": 0,
        "tagValuesQuery": "",
        "tags": [],
        "tagsQuery": "",
        "type": "query",
        "useTags": False,
    },
    {
        "allValue": ".*",
        "datasource": "${prometheusds}",
        "definition": 'label_values(up{juju_model=~"$juju_model",juju_model_uuid=~"$juju_model_uuid",juju_application=~"$juju_application"},juju_unit)',
        "description": None,
        "error": None,
        "hide": 0,
        "includeAll": True,
        "label": "Juju unit",
        "multi": True,
        "name": "juju_unit",
        "query": {
            "query": 'label_values(up{juju_model=~"$juju_model",juju_model_uuid=~"$juju_model_uuid",juju_application=~"$juju_application"},juju_unit)',
            "refId": "StandardVariableQuery",
        },
        "refresh": 1,
        "regex": "",
        "skipUrlSync": False,
        "sort": 0,
        "tagValuesQuery": "",
        "tags": [],
        "tagsQuery": "",
        "type": "query",
        "useTags": False,
    },
]

DATASOURCE_TEMPLATE_DROPDOWNS = [  # type: ignore
    {
        "description": None,
        "error": None,
        "hide": 0,
        "includeAll": True,
        "label": "Prometheus datasource",
        "multi": True,
        "name": "prometheusds",
        "options": [],
        "query": "prometheus",
        "refresh": 1,
        "regex": "",
        "skipUrlSync": False,
        "type": "datasource",
    },
    {
        "description": None,
        "error": None,
        "hide": 0,
        "includeAll": True,
        "label": "Loki datasource",
        "multi": True,
        "name": "lokids",
        "options": [],
        "query": "loki",
        "refresh": 1,
        "regex": "",
        "skipUrlSync": False,
        "type": "datasource",
    },
]

REACTIVE_CONVERTER = {  # type: ignore
    "allValue": None,
    "datasource": "${prometheusds}",
    "definition": 'label_values(up{juju_model=~"$juju_model",juju_model_uuid=~"$juju_model_uuid",juju_application=~"$juju_application"},host)',
    "description": None,
    "error": None,
    "hide": 0,
    "includeAll": True,
    "label": "hosts",
    "multi": True,
    "name": "host",
    "options": [],
    "query": {
        "query": 'label_values(up{juju_model=~"$juju_model",juju_model_uuid=~"$juju_model_uuid",juju_application=~"$juju_application"},host)',
        "refId": "StandardVariableQuery",
    },
    "refresh": 1,
    "regex": "",
    "skipUrlSync": False,
    "sort": 1,
    "tagValuesQuery": "",
    "tags": [],
    "tagsQuery": "",
    "type": "query",
    "useTags": False,
}


class CharmedDashboard:
    """A helper class for handling dashboards on the requirer (Grafana) side."""

    @classmethod
    def _convert_dashboard_fields(
        cls, content: str, inject_dropdowns: bool = True
    ) -> str:
        """Make sure values are present for Juju topology.

        Inserts Juju topology variables and selectors into the template, as well as
        a variable for Prometheus.
        """
        dict_content = json.loads(content)
        datasources = {}
        existing_templates = False

        template_dropdowns = (
            TOPOLOGY_TEMPLATE_DROPDOWNS + DATASOURCE_TEMPLATE_DROPDOWNS  # type: ignore
            if inject_dropdowns
            else DATASOURCE_TEMPLATE_DROPDOWNS
        )

        # If the dashboard has __inputs, get the names to replace them. These are stripped
        # from reactive dashboards in GrafanaDashboardAggregator, but charm authors in
        # newer charms may import them directly from the marketplace
        if "__inputs" in dict_content:
            for field in dict_content["__inputs"]:
                if "type" in field and field["type"] == "datasource":
                    datasources[field["name"]] = field["pluginName"].lower()
            del dict_content["__inputs"]

        # If no existing template variables exist, just insert our own
        if "templating" not in dict_content:
            dict_content["templating"] = {"list": list(template_dropdowns)}  # type: ignore
        else:
            # Otherwise, set a flag so we can go back later
            existing_templates = True
            for template_value in dict_content["templating"]["list"]:
                # Build a list of `datasource_name`: `datasource_type` mappings
                # The "query" field is actually "prometheus", "loki", "influxdb", etc
                if "type" in template_value and template_value["type"] == "datasource":
                    datasources[template_value["name"]] = template_value[
                        "query"
                    ].lower()

            # Put our own variables in the template
            for d in template_dropdowns:  # type: ignore
                if d not in dict_content["templating"]["list"]:
                    dict_content["templating"]["list"].insert(0, d)

        dict_content = cls._replace_template_fields(
            dict_content, datasources, existing_templates
        )
        return json.dumps(dict_content)

    @classmethod
    def _replace_template_fields(  # noqa: C901
        cls, dict_content: dict, datasources: dict, existing_templates: bool
    ) -> dict:
        """Make templated fields get cleaned up afterwards.

        If existing datasource variables are present, try to substitute them.
        """
        replacements = {"loki": "${lokids}", "prometheus": "${prometheusds}"}
        used_replacements: List[str] = []

        # If any existing datasources match types we know, or we didn't find
        # any templating variables at all, template them.
        if datasources or not existing_templates:
            panels = dict_content.get("panels", {})
            if panels:
                dict_content["panels"] = cls._template_panels(
                    panels,
                    replacements,
                    used_replacements,
                    existing_templates,
                    datasources,
                )

            # Find panels nested under rows
            rows = dict_content.get("rows", {})
            if rows:
                for row_idx, row in enumerate(rows):
                    if "panels" in row.keys():
                        rows[row_idx]["panels"] = cls._template_panels(
                            row["panels"],
                            replacements,
                            used_replacements,
                            existing_templates,
                            datasources,
                        )

                dict_content["rows"] = rows

        # Finally, go back and pop off the templates we stubbed out
        deletions = []
        for tmpl in dict_content["templating"]["list"]:
            if tmpl["name"] and tmpl["name"] in used_replacements:
                # it might happen that existing template var name is the same as the one we insert (i.e prometheusds or lokids)
                # in that case, we want to pop the existing one only.
                if tmpl not in DATASOURCE_TEMPLATE_DROPDOWNS:
                    deletions.append(tmpl)

        for d in deletions:
            dict_content["templating"]["list"].remove(d)

        return dict_content

    @classmethod
    def _template_panels(
        cls,
        panels: dict,
        replacements: dict,
        used_replacements: list,
        existing_templates: bool,
        datasources: dict,
    ) -> dict:
        """Iterate through a `panels` object and template it appropriately."""
        # Go through all the panels. If they have a datasource set, AND it's one
        # that we can convert to ${lokids} or ${prometheusds}, by stripping off the
        # ${} templating and comparing the name to the list we built, replace it,
        # otherwise, leave it alone.
        #
        for panel in panels:
            if "datasource" not in panel or not panel.get("datasource"):
                continue
            if not existing_templates:
                datasource = panel.get("datasource")
                if isinstance(datasource, str):
                    if "loki" in datasource:
                        panel["datasource"] = "${lokids}"
                    elif "grafana" in datasource:
                        continue
                    else:
                        panel["datasource"] = "${prometheusds}"
                elif isinstance(datasource, dict):
                    # In dashboards exported by Grafana 9, datasource type is dict
                    dstype = datasource.get("type", "")
                    if dstype == "loki":
                        panel["datasource"]["uid"] = "${lokids}"
                    elif dstype == "prometheus":
                        panel["datasource"]["uid"] = "${prometheusds}"
                    else:
                        logger.debug(
                            "Unrecognized datasource type '%s'; skipping", dstype
                        )
                        continue
                else:
                    logger.error("Unknown datasource format: skipping")
                    continue
            else:
                if isinstance(panel["datasource"], str):
                    if panel["datasource"].lower() in replacements.values():
                        # Already a known template variable
                        continue
                    # Strip out variable characters and maybe braces
                    ds = re.sub(r"(\$|\{|\})", "", panel["datasource"])

                    if ds not in datasources.keys():
                        # Unknown, non-templated datasource, potentially a Grafana builtin
                        continue

                    replacement = replacements.get(datasources[ds], "")
                    if replacement:
                        used_replacements.append(ds)
                    panel["datasource"] = replacement or panel["datasource"]
                elif isinstance(panel["datasource"], dict):
                    dstype = panel["datasource"].get("type", "")
                    if (
                        panel["datasource"].get("uid", "").lower()
                        in replacements.values()
                    ):
                        # Already a known template variable
                        continue
                    # Strip out variable characters and maybe braces
                    ds = re.sub(r"(\$|\{|\})", "", panel["datasource"].get("uid", ""))

                    if ds not in datasources.keys():
                        # Unknown, non-templated datasource, potentially a Grafana builtin
                        continue

                    replacement = replacements.get(datasources[ds], "")
                    if replacement:
                        used_replacements.append(ds)
                        panel["datasource"]["uid"] = replacement
                else:
                    logger.error("Unknown datasource format: skipping")
                    continue
        return panels

    @classmethod
    def _inject_labels(cls, content: str, topology: dict, transformer: CosTool) -> str:
        """Inject Juju topology into panel expressions via CosTool.

        A dashboard will have a structure approximating:
            {
                "__inputs": [],
                "templating": {
                    "list": [
                        {
                            "name": "prometheusds",
                            "type": "prometheus"
                        }
                    ]
                },
                "panels": [
                    {
                        "foo": "bar",
                        "targets": [
                            {
                                "some": "field",
                                "expr": "up{job="foo"}"
                            },
                            {
                                "some_other": "field",
                                "expr": "sum(http_requests_total{instance="$foo"}[5m])}
                            }
                        ],
                        "datasource": "${someds}"
                    }
                ]
            }

        `templating` is used elsewhere in this library, but the structure is not rigid. It is
        not guaranteed that a panel will actually have any targets (it could be a "spacer" with
        no datasource, hence no expression). It could have only one target. It could have multiple
        targets. It could have multiple targets of which only one has an `expr` to evaluate. We need
        to try to handle all of these concisely.

        `cos-tool` (`github.com/canonical/cos-tool` as a Go module in general)
        does not know "Grafana-isms", such as using `[$_variable]` to modify the query from the user
        interface, so we add placeholders (as `5y`, since it must parse, but a dashboard looking for
        five years for a panel query would be unusual).

        Args:
            content: dashboard content as a string
            topology: a dict containing topology values
            transformer: a 'CosTool' instance
        Returns:
            dashboard content with replaced values.
        """
        dict_content = json.loads(content)

        if "panels" not in dict_content.keys():
            return json.dumps(dict_content)

        # Go through all the panels and inject topology labels
        # Panels may have more than one 'target' where the expressions live, so that must be
        # accounted for. Additionally, `promql-transform` does not necessarily gracefully handle
        # expressions with range queries including variables. Exclude these.
        #
        # It is not a certainty that the `datasource` field will necessarily reflect the type, so
        # operate on all fields.
        panels = dict_content["panels"]
        topology_with_prefix = {"juju_{}".format(k): v for k, v in topology.items()}

        # We need to use an index so we can insert the changed element back later
        for panel_idx, panel in enumerate(panels):
            if not isinstance(panel, dict):
                continue

            # Use the index to insert it back in the same location
            panels[panel_idx] = cls._modify_panel(
                panel, topology_with_prefix, transformer
            )

        return json.dumps(dict_content)

    @classmethod
    def _modify_panel(cls, panel: dict, topology: dict, transformer: CosTool) -> dict:
        """Inject Juju topology into panel expressions via CosTool.

        Args:
            panel: a dashboard panel as a dict
            topology: a dict containing topology values
            transformer: a 'CosTool' instance
        Returns:
            the panel with injected values
        """
        if "targets" not in panel.keys():
            return panel

        # Pre-compile a regular expression to grab values from inside of []
        range_re = re.compile(r"\[(?P<value>.*?)\]")
        # Do the same for any offsets
        offset_re = re.compile(r"offset\s+(?P<value>-?\s*[$\w]+)")

        known_datasources = {"${prometheusds}": "promql", "${lokids}": "logql"}

        targets = panel["targets"]

        # We need to use an index so we can insert the changed element back later
        for idx, target in enumerate(targets):
            # If there's no expression, we don't need to do anything
            if "expr" not in target.keys():
                continue
            expr = target["expr"]

            if "datasource" not in panel.keys():
                continue

            if isinstance(panel["datasource"], str):
                if panel["datasource"] not in known_datasources:
                    continue
                querytype = known_datasources[panel["datasource"]]
            elif isinstance(panel["datasource"], dict):
                if panel["datasource"]["uid"] not in known_datasources:
                    continue
                querytype = known_datasources[panel["datasource"]["uid"]]
            else:
                logger.error("Unknown datasource format: skipping")
                continue

            # Capture all values inside `[]` into a list which we'll iterate over later to
            # put them back in-order. Then apply the regex again and replace everything with
            # `[5y]` so promql/parser will take it.
            #
            # Then do it again for offsets
            range_values = [m.group("value") for m in range_re.finditer(expr)]
            expr = range_re.sub(r"[5y]", expr)

            offset_values = [m.group("value") for m in offset_re.finditer(expr)]
            expr = offset_re.sub(r"offset 5y", expr)
            # Retrieve the new expression (which may be unchanged if there were no label
            # matchers in the expression, or if tt was unable to be parsed like logql. It's
            # virtually impossible to tell from any datasource "name" in a panel what the
            # actual type is without re-implementing a complete dashboard parser, but no
            # harm will some from passing invalid promql -- we'll just get the original back.
            normalized_querytype = (
                querytype if querytype in ["promql", "logql"] else None
            )
            replacement = transformer.inject_label_matchers(
                expr,
                topology,
                normalized_querytype or "promql",  # type: ignore
            )

            if replacement == target["expr"]:
                # promql-transform caught an error. Move on
                continue

            # Go back and substitute values in [] which were pulled out
            # Enumerate with an index... again. The same regex is ok, since it will still match
            # `[(.*?)]`, which includes `[5y]`, our placeholder
            for i, match in enumerate(range_re.finditer(replacement)):
                # Replace one-by-one, starting from the left. We build the string back with
                # `str.replace(string_to_replace, replacement_value, count)`. Limit the count
                # to one, since we are going through one-by-one through the list we saved earlier
                # in `range_values`.
                replacement = replacement.replace(
                    "[{}]".format(match.group("value")),
                    "[{}]".format(range_values[i]),
                    1,
                )

            for i, match in enumerate(offset_re.finditer(replacement)):
                # Replace one-by-one, starting from the left. We build the string back with
                # `str.replace(string_to_replace, replacement_value, count)`. Limit the count
                # to one, since we are going through one-by-one through the list we saved earlier
                # in `range_values`.
                replacement = replacement.replace(
                    "offset {}".format(match.group("value")),
                    "offset {}".format(offset_values[i]),
                    1,
                )

            # Use the index to insert it back in the same location
            targets[idx]["expr"] = replacement

        panel["targets"] = targets
        return panel

    @classmethod
    def _content_to_dashboard_object(
        cls,
        *,
        charm_name,
        content: str,
        juju_topology: dict,
        inject_dropdowns: bool = True,
        dashboard_alt_uid: Optional[str] = None,
    ) -> Dict:
        """Helper method for keeping a consistent stored state schema for the dashboard and some metadata.

        Args:
            charm_name: Charm name (although the aggregator passes the app name).
            content: The compressed dashboard.
            juju_topology: This is not actually used in the dashboards, but is present to provide a secondary
              salt to ensure uniqueness in the dict keys in case individual charm units provide dashboards.
            inject_dropdowns: Whether to auto-render topology dropdowns.
            dashboard_alt_uid: Alternative uid used for dashboards added programmatically.
        """
        ret = {
            "charm": charm_name,
            "content": content,
            "juju_topology": juju_topology if inject_dropdowns else {},
            "inject_dropdowns": inject_dropdowns,
        }

        if dashboard_alt_uid is not None:
            ret["dashboard_alt_uid"] = dashboard_alt_uid

        return ret

    @classmethod
    def _generate_alt_uid(cls, charm_name: str, key: str) -> str:
        """Generate alternative uid for dashboards.

        Args:
            charm_name: The name of the charm (not app; from metadata).
            key: A string used (along with charm.meta.name) to build the hash uid.

        Returns: A hash string.
        """
        raw_dashboard_alt_uid = "{}-{}".format(charm_name, key)
        return hashlib.shake_256(raw_dashboard_alt_uid.encode("utf-8")).hexdigest(8)

    @classmethod
    def _replace_uid(
        cls,
        *,
        dashboard_dict: dict,
        dashboard_path: Path,
        charm_dir: Path,
        charm_name: str,
    ):
        # If we're running this from within an aggregator (such as grafana agent), then the uid was
        # already rendered there, so we do not want to overwrite it with a uid generated from aggregator's info.
        # We overwrite the uid only if it's not a valid "Path40" uid.
        if not DashboardPath40UID.is_valid(
            original_uid := dashboard_dict.get("uid", "")
        ):
            rel_path = str(
                dashboard_path.relative_to(charm_dir)
                if dashboard_path.is_absolute()
                else dashboard_path
            )
            dashboard_dict["uid"] = DashboardPath40UID.generate(charm_name, rel_path)
            logger.debug(
                "Processed dashboard '%s': replaced original uid '%s' with '%s'",
                dashboard_path,
                original_uid,
                dashboard_dict["uid"],
            )
        else:
            logger.debug(
                "Processed dashboard '%s': kept original uid '%s'",
                dashboard_path,
                original_uid,
            )

    @classmethod
    def _add_tags(cls, dashboard_dict: dict, charm_name: str):
        tags: List[str] = dashboard_dict.get("tags", [])
        if not any(tag.startswith("charm: ") for tag in tags):
            tags.append(f"charm: {charm_name}")
        dashboard_dict["tags"] = tags

    @classmethod
    def load_dashboards_from_dir(
        cls,
        *,
        dashboards_path: Path,
        charm_name: str,
        charm_dir: Path,
        inject_dropdowns: bool,
        juju_topology: dict,
        path_filter: Callable[[Path], bool] = lambda p: True,
    ) -> dict:
        """Load dashboards files from directory into a mapping from "dashboard id" to a so-called "dashboard object"."""

        # Path.glob uses fnmatch on the backend, which is pretty limited, so use a
        # custom function for the filter
        def _is_dashboard(p: Path) -> bool:
            return (
                p.is_file()
                and p.name.endswith((".json", ".json.tmpl", ".tmpl"))
                and path_filter(p)
            )

        dashboard_templates = {}

        for path in filter(_is_dashboard, Path(dashboards_path).glob("*")):
            try:
                dashboard_dict = json.loads(path.read_bytes())
            except json.JSONDecodeError as e:
                logger.error("Failed to load dashboard '%s': %s", path, e)
                continue
            if type(dashboard_dict) is not dict:
                logger.error(
                    "Invalid dashboard '%s': expected dict, got %s",
                    path,
                    type(dashboard_dict),
                )

            cls._replace_uid(
                dashboard_dict=dashboard_dict,
                dashboard_path=path,
                charm_dir=charm_dir,
                charm_name=charm_name,
            )

            cls._add_tags(dashboard_dict=dashboard_dict, charm_name=charm_name)

            id = "file:{}".format(path.stem)
            dashboard_templates[id] = cls._content_to_dashboard_object(
                charm_name=charm_name,
                content=LZMABase64.compress(json.dumps(dashboard_dict)),
                dashboard_alt_uid=cls._generate_alt_uid(charm_name, id),
                inject_dropdowns=inject_dropdowns,
                juju_topology=juju_topology,
            )

        return dashboard_templates
