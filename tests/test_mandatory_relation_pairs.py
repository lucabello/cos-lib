# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

from cosl.mandatory_relation_pairs import MandatoryRelationPairs


class TestMandatoryRelationPairs(unittest.TestCase):
    def setUp(self):
        self.rels = {
            "juju-info": [  # must be paired with:
                {"grafana-cloud-config"},  # or
                {"send-remote-write", "logging-consumer"},
            ],
            "cos-agent": [  # must be paired with:
                {"grafana-cloud-config"},  # or
                {"send-remote-write", "logging-consumer", "grafana-dashboards-provider"},
            ],
        }

    def test_unspecified(self):
        mrp = MandatoryRelationPairs(self.rels.copy())
        self.assertEqual(mrp.get_missing(), {})
        self.assertEqual(mrp.get_missing("some_unspecified_relation"), {})

        # Should be ok if "outgoing" are specified without "incoming".
        self.assertEqual(mrp.get_missing("grafana-cloud-config"), {})
        self.assertEqual(mrp.get_missing("logging-consumer"), {})

    def test_incoming(self):
        """One or more of the 'incoming' relations are the only ones present."""
        mrp = MandatoryRelationPairs(self.rels.copy())
        self.assertEqual(
            mrp.get_missing("cos-agent"),
            {"cos-agent": self.rels["cos-agent"]},
        )
        self.assertEqual(mrp.get_missing(*self.rels.keys()), self.rels)

    def test_match(self):
        """An 'incoming' relation has all its required matching 'outgoing' relations."""
        mrp = MandatoryRelationPairs(self.rels.copy())
        self.assertEqual(mrp.get_missing("cos-agent", "grafana-cloud-config"), {})
        self.assertEqual(
            mrp.get_missing(
                "cos-agent",
                "grafana-cloud-config",
                "send-remote-write",
                "some-unspecified-relation",
            ),
            {},
        )
        self.assertEqual(
            mrp.get_missing(
                "cos-agent",
                "send-remote-write",
                "logging-consumer",
                "grafana-dashboards-provider",
            ),
            {},
        )
        self.assertEqual(
            mrp.get_missing(
                "cos-agent",
                "juju-info",
                "send-remote-write",
                "logging-consumer",
                "grafana-dashboards-provider",
            ),
            {},
        )

    def test_under_match(self):
        mrp = MandatoryRelationPairs(self.rels.copy())
        self.assertEqual(
            mrp.get_missing("juju-info", "send-remote-write"),
            {"juju-info": [{"grafana-cloud-config"}, {"logging-consumer"}]},
        )
        self.assertEqual(
            mrp.get_missing("cos-agent", "juju-info", "send-remote-write", "logging-consumer"),
            {"cos-agent": [{"grafana-cloud-config"}, {"grafana-dashboards-provider"}]},
        )

    def test_under_match_as_str(self):
        mrp = MandatoryRelationPairs(self.rels.copy())
        self.assertEqual(
            mrp.get_missing_as_str("juju-info"),
            "['grafana-cloud-config']|['logging-consumer', 'send-remote-write'] for juju-info",
        )
        self.assertEqual(
            mrp.get_missing_as_str("juju-info", "cos-agent"),
            "['grafana-cloud-config']|['grafana-dashboards-provider', 'logging-consumer', 'send-remote-write'] for cos-agent; ['grafana-cloud-config']|['logging-consumer', 'send-remote-write'] for juju-info",
        )
