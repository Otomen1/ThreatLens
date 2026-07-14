"""Tests for the Evidence Relationship Graph Engine (Phase 8.2).

These tests exist to make the brief's "Critical Design Rule" a checked fact,
not a comment: a node or edge may exist only when supported by existing
evidence or an explicit existing relationship. No invented entities, no
invented relationships, no connections drawn merely from co-occurrence,
stable ids, stable ordering, no duplicate canonical elements.
"""

from __future__ import annotations

from datetime import UTC, datetime

from threatlens.correlation.models import CorrelationRelationshipType
from threatlens.entities.types import EntityType
from threatlens.graph.engine import (
    CORRELATED_WITH,
    OBSERVATION_NODE_TYPE,
    collect_graph,
    compute_edge_id,
    compute_node_id,
    sort_edges,
    sort_nodes,
)
from threatlens.providers.results import RelationshipTargetType, RelationshipType
from threatlens.reasoning.models import FindingCategory, Severity

from .factories import (
    correlation_evidence,
    correlation_relationship,
    correlation_summary,
    finding,
    observation,
    relationship,
    summary,
)

T1 = datetime(2024, 1, 1, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# collect_graph — findings as the evidence source
# --------------------------------------------------------------------------- #


class TestCollectGraphFromFindings:
    def test_empty_investigation_yields_empty_graph(self) -> None:
        nodes, edges = collect_graph(summary([]), None)
        assert nodes == ()
        assert edges == ()

    def test_finding_with_no_relationships_yields_one_node_no_edges(self) -> None:
        nodes, edges = collect_graph(summary([finding("f1")]), None)
        assert len(nodes) == 1
        assert edges == ()
        assert nodes[0].node_type == "ipv4"
        assert nodes[0].value == "8.8.8.8"

    def test_relationship_produces_subject_and_target_nodes_plus_one_edge(self) -> None:
        f = finding("f1", relationships=[relationship()])
        nodes, edges = collect_graph(summary([f]), None)
        assert len(nodes) == 2
        assert len(edges) == 1
        assert edges[0].relationship_type == RelationshipType.ASSOCIATED_WITH.value

    def test_edge_connects_the_correct_nodes(self) -> None:
        f = finding("f1", relationships=[relationship()])
        nodes, edges = collect_graph(summary([f]), None)
        by_value = {n.value: n for n in nodes}
        edge = edges[0]
        assert edge.source_node_id == by_value["8.8.8.8"].node_id
        assert edge.target_node_id == by_value["Emotet"].node_id

    def test_severity_copied_from_subject_finding_never_recomputed(self) -> None:
        f = finding("f1", severity=Severity.CRITICAL)
        nodes, _ = collect_graph(summary([f]), None)
        assert nodes[0].severity == Severity.CRITICAL

    def test_relationship_target_only_entity_has_no_severity(self) -> None:
        f = finding("f1", severity=Severity.HIGH, relationships=[relationship()])
        nodes, _ = collect_graph(summary([f]), None)
        target = next(n for n in nodes if n.value == "Emotet")
        assert target.severity is None

    def test_explanation_falls_back_to_empty_string_when_description_is_none(self) -> None:
        f = finding("f1", relationships=[relationship(description=None)])
        _, edges = collect_graph(summary([f]), None)
        assert edges[0].explanation == ""

    def test_evidence_and_source_references_are_the_finding_id(self) -> None:
        f = finding("f1", relationships=[relationship()])
        _, edges = collect_graph(summary([f]), None)
        assert edges[0].evidence_references == ("f1",)
        assert edges[0].source_references == ("f1",)


# --------------------------------------------------------------------------- #
# Canonicalization — vocabulary alignment, never speculative
# --------------------------------------------------------------------------- #


class TestCanonicalization:
    def test_shared_string_value_across_entitytype_and_relationshiptargettype_collapses(
        self,
    ) -> None:
        """EntityType.MALWARE_FAMILY and RelationshipTargetType.MALWARE_FAMILY share
        the identical string value, so a finding's own subject and another
        finding's relationship target must resolve to one canonical node."""
        f1 = finding("f1", relationships=[relationship()])  # targets "Emotet"
        f2 = finding(
            "f2",
            categories=[FindingCategory.MALWARE],
            subject_type=EntityType.MALWARE_FAMILY,
            subject_value="Emotet",
            severity=Severity.CRITICAL,
        )
        nodes, _ = collect_graph(summary([f1, f2]), None)
        emotet_nodes = [n for n in nodes if n.value == "Emotet"]
        assert len(emotet_nodes) == 1
        assert emotet_nodes[0].severity == Severity.CRITICAL  # from f2's own subject
        assert set(emotet_nodes[0].source_references) == {"f1", "f2"}

    def test_distinct_vocabularies_are_never_speculatively_merged(self) -> None:
        """RelationshipTargetType.VULNERABILITY has no EntityType counterpart with
        the same string value; it must remain its own node, never remapped."""
        f = finding(
            "f1",
            relationships=[
                relationship(
                    target_type=RelationshipTargetType.VULNERABILITY,
                    target_value="CVE-2024-9999",
                )
            ],
        )
        nodes, _ = collect_graph(summary([f]), None)
        target = next(n for n in nodes if n.value == "CVE-2024-9999")
        assert target.node_type == "vulnerability"

    def test_value_canonicalization_is_case_and_whitespace_insensitive(self) -> None:
        a = compute_node_id(node_type="malware_family", value="Emotet")
        b = compute_node_id(node_type="malware_family", value="  emotet  ")
        assert a == b


# --------------------------------------------------------------------------- #
# Deduplication
# --------------------------------------------------------------------------- #


class TestDeduplication:
    def test_identical_relationship_asserted_by_two_findings_collapses_to_one_edge(
        self,
    ) -> None:
        f1 = finding("f1", relationships=[relationship()])
        f2 = finding(
            "f2",
            categories=[FindingCategory.REPUTATION],
            severity=Severity.CRITICAL,
            relationships=[relationship()],
        )
        _, edges = collect_graph(summary([f1, f2]), None)
        assert len(edges) == 1
        assert set(edges[0].evidence_references) == {"f1", "f2"}

    def test_same_subject_across_two_findings_is_one_node(self) -> None:
        f1 = finding("f1", severity=Severity.LOW)
        f2 = finding("f2", categories=[FindingCategory.REPUTATION], severity=Severity.CRITICAL)
        nodes, _ = collect_graph(summary([f1, f2]), None)
        assert len(nodes) == 1
        assert nodes[0].severity == Severity.CRITICAL  # worst of LOW/CRITICAL


# --------------------------------------------------------------------------- #
# collect_graph — correlation observations as the evidence source
# --------------------------------------------------------------------------- #


class TestCollectGraphFromObservations:
    def test_observation_with_no_correlation_summary_produces_no_observation_nodes(
        self,
    ) -> None:
        nodes, _ = collect_graph(summary([finding("f1")]), None)
        assert all(n.node_type != OBSERVATION_NODE_TYPE for n in nodes)

    def test_observation_with_one_distinct_entity_yields_one_hub_edge(self) -> None:
        s = summary([finding("f1"), finding("f2", categories=[FindingCategory.EXPOSURE])])
        corr = correlation_summary(
            [
                observation(
                    "cor_1",
                    evidence_items=[
                        correlation_evidence("f1"),
                        correlation_evidence("f2", matched_category=FindingCategory.EXPOSURE),
                    ],
                )
            ]
        )
        nodes, edges = collect_graph(s, corr)
        hub_edges = [e for e in edges if e.relationship_type == CORRELATED_WITH]
        assert len(hub_edges) == 1
        assert set(hub_edges[0].evidence_references) == {"f1", "f2"}
        observation_node = next(n for n in nodes if n.node_type == OBSERVATION_NODE_TYPE)
        assert observation_node.label == "Test observation"
        assert observation_node.metadata["rule_id"] == "test_rule"

    def test_observation_with_two_entities_yields_two_hub_edges_and_direct_edge(self) -> None:
        s = summary(
            [
                finding("f1", categories=[FindingCategory.MALWARE]),
                finding(
                    "f2",
                    categories=[FindingCategory.ATTACK_PATTERN],
                    subject_type=EntityType.MITRE_TECHNIQUE,
                    subject_value="T1059",
                ),
            ]
        )
        corr = correlation_summary(
            [
                observation(
                    "cor_2",
                    evidence_items=[
                        correlation_evidence("f1", matched_category=FindingCategory.MALWARE),
                        correlation_evidence(
                            "f2",
                            matched_category=FindingCategory.ATTACK_PATTERN,
                            subject_type=EntityType.MITRE_TECHNIQUE,
                            subject_value="T1059",
                        ),
                    ],
                    relationships=[
                        correlation_relationship(
                            source_finding_id="f1",
                            target_finding_id="f2",
                            rel_type=CorrelationRelationshipType.MAPPED_TO,
                        )
                    ],
                )
            ]
        )
        nodes, edges = collect_graph(s, corr)
        hub_edges = [e for e in edges if e.relationship_type == CORRELATED_WITH]
        direct_edges = [
            e for e in edges if e.relationship_type == CorrelationRelationshipType.MAPPED_TO.value
        ]
        assert len(hub_edges) == 2
        assert len(direct_edges) == 1
        by_value = {n.value: n for n in nodes}
        assert direct_edges[0].source_node_id == by_value["8.8.8.8"].node_id
        assert direct_edges[0].target_node_id == by_value["T1059"].node_id
        assert direct_edges[0].source_references == ("cor_2",)

    def test_same_subject_correlation_relationship_is_not_a_self_loop(self) -> None:
        """f1/f2 share one subject; the correlation relationship between them
        must not become a self-loop edge — only the hub edges connect to it."""
        s = summary([finding("f1"), finding("f2", categories=[FindingCategory.EXPOSURE])])
        corr = correlation_summary(
            [
                observation(
                    "cor_3",
                    evidence_items=[
                        correlation_evidence("f1"),
                        correlation_evidence("f2", matched_category=FindingCategory.EXPOSURE),
                    ],
                    relationships=[
                        correlation_relationship(source_finding_id="f1", target_finding_id="f2")
                    ],
                )
            ]
        )
        _, edges = collect_graph(s, corr)
        assert all(e.source_node_id != e.target_node_id for e in edges)
        assert len(edges) == 1  # only the one hub edge to the shared subject

    def test_relationship_referencing_an_unknown_finding_is_skipped(self) -> None:
        s = summary([finding("f1")])
        corr = correlation_summary(
            [
                observation(
                    "cor_4",
                    evidence_items=[correlation_evidence("f1")],
                    relationships=[
                        correlation_relationship(source_finding_id="f1", target_finding_id="f9")
                    ],
                )
            ]
        )
        nodes, edges = collect_graph(s, corr)
        assert len(edges) == 1  # only the hub edge; the direct edge was skipped
        assert edges[0].relationship_type == CORRELATED_WITH

    def test_two_observations_sharing_an_entity_produce_one_node_two_hub_edges(self) -> None:
        s = summary([finding("f1"), finding("f2", categories=[FindingCategory.EXPOSURE])])
        corr = correlation_summary(
            [
                observation("cor_5", evidence_items=[correlation_evidence("f1")]),
                observation(
                    "cor_6",
                    evidence_items=[
                        correlation_evidence("f2", matched_category=FindingCategory.EXPOSURE)
                    ],
                ),
            ]
        )
        nodes, edges = collect_graph(s, corr)
        entity_nodes = [n for n in nodes if n.node_type == "ipv4"]
        hub_edges = [e for e in edges if e.relationship_type == CORRELATED_WITH]
        assert len(entity_nodes) == 1
        assert len(hub_edges) == 2

    def test_correlation_summary_with_no_observations_yields_no_observation_nodes(self) -> None:
        s = summary([finding("f1")])
        corr = correlation_summary([])
        nodes, _ = collect_graph(s, corr)
        assert all(n.node_type != OBSERVATION_NODE_TYPE for n in nodes)


# --------------------------------------------------------------------------- #
# compute_node_id / compute_edge_id — content-addressed identity
# --------------------------------------------------------------------------- #


class TestComputeNodeId:
    def test_deterministic_for_identical_input(self) -> None:
        a = compute_node_id(node_type="ipv4", value="1.2.3.4")
        b = compute_node_id(node_type="ipv4", value="1.2.3.4")
        assert a == b

    def test_differs_when_type_differs(self) -> None:
        a = compute_node_id(node_type="ipv4", value="x")
        b = compute_node_id(node_type="domain", value="x")
        assert a != b

    def test_differs_when_value_differs(self) -> None:
        a = compute_node_id(node_type="ipv4", value="1.2.3.4")
        b = compute_node_id(node_type="ipv4", value="9.9.9.9")
        assert a != b

    def test_never_includes_current_time(self) -> None:
        import time

        a = compute_node_id(node_type="ipv4", value="1.2.3.4")
        time.sleep(0.01)
        b = compute_node_id(node_type="ipv4", value="1.2.3.4")
        assert a == b

    def test_prefixed_and_stable_length(self) -> None:
        node_id = compute_node_id(node_type="ipv4", value="1.2.3.4")
        assert node_id.startswith("node_")
        assert len(node_id) == len("node_") + 16


class TestComputeEdgeId:
    def test_deterministic_for_identical_input(self) -> None:
        a = compute_edge_id(source_node_id="s", target_node_id="t", relationship_type="uses")
        b = compute_edge_id(source_node_id="s", target_node_id="t", relationship_type="uses")
        assert a == b

    def test_differs_when_relationship_type_differs(self) -> None:
        a = compute_edge_id(source_node_id="s", target_node_id="t", relationship_type="uses")
        b = compute_edge_id(source_node_id="s", target_node_id="t", relationship_type="exploits")
        assert a != b

    def test_excludes_evidence_so_repeated_assertions_share_one_edge(self) -> None:
        """Identity intentionally omits evidence references — this is exactly
        what lets two independent findings asserting the same relationship
        collapse into one edge instead of minting duplicates."""
        a = compute_edge_id(source_node_id="s", target_node_id="t", relationship_type="uses")
        b = compute_edge_id(source_node_id="s", target_node_id="t", relationship_type="uses")
        assert a == b

    def test_prefixed_and_stable_length(self) -> None:
        edge_id = compute_edge_id(source_node_id="s", target_node_id="t", relationship_type="uses")
        assert edge_id.startswith("edge_")
        assert len(edge_id) == len("edge_") + 16


# --------------------------------------------------------------------------- #
# sort_nodes / sort_edges — deterministic ordering
# --------------------------------------------------------------------------- #


class TestSortOrdering:
    def test_nodes_ordered_by_type_then_value_then_id(self) -> None:
        f = finding(
            "f1",
            relationships=[
                relationship(target_type=RelationshipTargetType.CAMPAIGN, target_value="Zeta"),
                relationship(target_type=RelationshipTargetType.CAMPAIGN, target_value="Alpha"),
            ],
        )
        nodes, _ = collect_graph(summary([f]), None)
        campaign_values = [n.value for n in nodes if n.node_type == "campaign"]
        assert campaign_values == sorted(campaign_values)

    def test_edges_ordered_by_relationship_type_then_source_then_target(self) -> None:
        f = finding(
            "f1",
            relationships=[
                relationship(verb=RelationshipType.USES, target_value="Z"),
                relationship(verb=RelationshipType.EXPLOITS, target_value="A"),
            ],
        )
        _, edges = collect_graph(summary([f]), None)
        assert [e.relationship_type for e in edges] == sorted(e.relationship_type for e in edges)

    def test_reordering_input_findings_does_not_change_output(self) -> None:
        f1 = finding("f1", relationships=[relationship(target_value="A")])
        f2 = finding(
            "f2",
            categories=[FindingCategory.REPUTATION],
            relationships=[relationship(target_value="B")],
        )
        forward = collect_graph(summary([f1, f2]), None)
        backward = collect_graph(summary([f2, f1]), None)
        assert forward == backward

    def test_sort_functions_are_pure_and_repeatable(self) -> None:
        f = finding(
            "f1",
            relationships=[relationship(target_value="A"), relationship(target_value="B")],
        )
        nodes, edges = collect_graph(summary([f]), None)
        assert sort_nodes(nodes) == sort_nodes(tuple(reversed(nodes)))
        assert sort_edges(edges) == sort_edges(tuple(reversed(edges)))


# --------------------------------------------------------------------------- #
# Read-only behavior — inputs are never mutated
# --------------------------------------------------------------------------- #


class TestReadOnly:
    def test_input_summary_unchanged_after_collection(self) -> None:
        f = finding("f1", relationships=[relationship()])
        source = summary([f])
        before = source.model_dump_json()
        collect_graph(source, None)
        after = source.model_dump_json()
        assert before == after

    def test_input_correlation_unchanged_after_collection(self) -> None:
        s = summary([finding("f1")])
        corr = correlation_summary(
            [observation("cor_1", evidence_items=[correlation_evidence("f1")])]
        )
        before = corr.model_dump_json()
        collect_graph(s, corr)
        after = corr.model_dump_json()
        assert before == after
