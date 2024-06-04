# cosl
![PyPI](https://img.shields.io/pypi/v/cosl)

This library provides utilities for
[COS Lite](https://github.com/canonical/cos-lite-bundle/) charms:

- [`CosTool`](src/cosl/cos_tool.py): bindings for
  [cos-tool](https://github.com/canonical/cos-tool)
- [`JujuTopology`](src/cosl/juju_topology.py): logic for
  [topology labels](https://ubuntu.com/blog/model-driven-observability-part-2-juju-topology-metrics)
- [`LokiHandler`](src/cosl/loki_logger.py): python logging handler that forwards logs to a Loki push api endpoint.

