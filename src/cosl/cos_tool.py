import logging
import platform
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Literal, Optional

import ops

logger = logging.getLogger(__name__)


class CosTool:
    def __init__(self):
        # Get executable path
        arch = platform.machine()
        arch = "amd64" if arch == "x86_64" else arch
        res = "cos-tool-{}".format(arch)
        try:
            path = Path(res).resolve(strict=True)
        except (FileNotFoundError, OSError):
            logger.debug('Could not locate cos-tool at: "{}"'.format(res))
            path = None
        self._executable: Optional[Path] = path

    def run(self, args: List[str]) -> str:
        """Run a cos-tool command and return its stdout."""
        result = subprocess.run(["cos-tool", *args], check=True, stdout=subprocess.PIPE)
        return result.stdout.decode("utf-8").strip()

    def inject_label_matchers(
        self, expression: str, topology: Dict, expression_type: Literal["promql", "logql"]
    ) -> str:
        """Add label matchers to an expression.

        Return the rule expression.
        """
        if not topology:
            return expression
        if not self._executable:
            logger.debug("`cos-tool` unavailable. Leaving expression unchanged: %s", expression)
            return expression
        args = ["--format", expression_type, "transform"]

        variable_topology = {k: "${}".format(k) for k in topology.keys()}
        args.extend(
            [
                "--label-matcher={}={}".format(key, value)
                for key, value in variable_topology.items()
            ]
        )

        # Pass a leading "--" so expressions with a negation or subtraction aren't interpreted as flags
        args.extend(["--", expression])
        try:
            return re.sub(r'="\$juju', r'=~"$juju', self.run(args))
        except subprocess.CalledProcessError as e:
            logger.debug('Applying the expression failed: "%s", falling back to the original', e)
            return expression
