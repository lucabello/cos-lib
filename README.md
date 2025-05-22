# cosl
![PyPI](https://img.shields.io/pypi/v/cosl)

> [!NOTE]
> The `coordinated_workers` module and its related support files have been removed from `cosl`. This functionality now lives in a standalone [coordinated-workers](https://github.com/canonical/cos-coordinated-workers) PyPI package. Please migrate to that package. 


This library provides utilities for
[COS Lite](https://github.com/canonical/cos-lite-bundle/) charms:

- [`CosTool`](src/cosl/cos_tool.py): bindings for
  [cos-tool](https://github.com/canonical/cos-tool)
- [`JujuTopology`](src/cosl/juju_topology.py): logic for
  [topology labels](https://ubuntu.com/blog/model-driven-observability-part-2-juju-topology-metrics)
- [`LokiHandler`](src/cosl/loki_logger.py): python logging handler that forwards logs to a Loki push api endpoint.

# How to release
 
Go to https://github.com/canonical/cos-lib/releases and click on 'Draft a new release'.

Select a tag from the dropdown, or create a new one from the `main` target branch.

Enter a meaningful release title and in the description, put an itemized changelog listing new features and bugfixes, and whatever is good to mention.

Click on 'Publish release'.