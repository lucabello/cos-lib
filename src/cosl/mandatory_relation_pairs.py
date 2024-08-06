# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tooling for rendering charm status message for mandatory relation pairs."""

from typing import Dict, List, Set


class MandatoryRelationPairs:
    """A helper class for ensuring that an incoming relation has a matching outgoing relation.

    >>> # "rel1" must be paired with (both "r1" and "r2") or "r3", and "rel2" with "r4"
    >>> mrp = MandatoryRelationPairs({"rel1": [{"r1", "r2"}, {"r3"}], "rel2": [{"r4"}]})
    >>> mrp.get_missing_as_str("rel1", "r1", "rel2")
    "['r2']|['r3'] for rel1; ['r4'] for rel2"
    >>> mrp.get_missing_as_str("rel1", "r3")
    ''
    >>> mrp.get_missing_as_str()
    ''
    """

    def __init__(self, pairs: Dict[str, List[Set[str]]]):
        # pairs look like this:
        # {
        #     "cos-agent": [  # must be paired with:
        #         {"grafana-cloud-config"},  # or
        #         {"send-remote-write", "logging-consumer", "grafana-dashboards-provider"},
        #     ],
        #     "juju-info": [  # must be paired with:
        #         {"grafana-cloud-config"},  # or
        #         {"send-remote-write", "logging-consumer"},
        #     ],
        # }
        self._pairs = pairs

    def get_missing(self, *relations_present: str) -> Dict[str, List[Set[str]]]:
        """Returns a mapping from relation name to the set of missing mandatory relation names.

        If nothing is missing for a given relation, then it won't be listed (as a key) in the dict.
        """
        # From all relations currently present, get a set of 'incoming' relations that must
        # have matching 'outgoing' relations.
        relations_incoming: Set[str] = set(relations_present).intersection(self._pairs.keys())

        # Same shape as `self._pairs`
        missing = {
            rel: [mandatory.difference(relations_present) for mandatory in self._pairs[rel]]
            for rel in relations_incoming
        }

        # If any rel in missing has an empty set, it means that it has at least one combo of
        # matching relations, so that rel can be dropped out of `missing`.
        missing = {k: v for k, v in missing.items() if all(v)}

        return missing

    def get_missing_as_str(self, *relations_present: str) -> str:
        """Return the missing relations, formatted into a string."""
        missing = self.get_missing(*relations_present)

        combos = "; ".join(
            sorted(
                [
                    "|".join(sorted([str(sorted(mandatory)) for mandatory in v])) + f" for {rel}"
                    for rel, v in sorted(missing.items())
                ]
            )
        )

        return f"{combos}" if combos else ""
