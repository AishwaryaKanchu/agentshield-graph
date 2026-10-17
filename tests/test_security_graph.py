"""Tests synthetic security graph initialization, multi-hop Cypher queries,

and simulated permission-revocation verification.
"""

import pytest
from src.init_db import init_database
from src.security_graph import (
    trace_untrusted_confidential_paths,
    trace_incident_blast_radius,
    revoke_permission,
    restore_permission,
    get_all_agents,
)


@pytest.fixture(scope="module")
def seeded_graph():
    """Ensure a fresh synthetic security graph is initialized in FalkorDB."""
    g = init_database(graph_name="agentshield_test", clear_existing=True)
    yield g
    # Clean up test graph after tests
    try:
        g.delete()
    except Exception:
        pass


def test_graph_initialization_nodes_and_edges(seeded_graph):
    """Verify that all security entities and relationships are populated."""
    node_res = seeded_graph.query("MATCH (n) RETURN count(n) AS cnt")
    assert node_res.result_set[0][0] >= 14, "Expected at least 14 nodes in security graph"

    rel_res = seeded_graph.query("MATCH ()-[r]->() RETURN count(r) AS cnt")
    assert rel_res.result_set[0][0] >= 10, "Expected at least 10 relationships in security graph"


def test_multi_hop_untrusted_path_detection(seeded_graph):
    """Verify that Cypher successfully traces the multi-hop vulnerability:

    (User) -> (Low-Trust Agent) -> (Critical Tool) -> (Confidential Resource)
    """
    paths = trace_untrusted_confidential_paths(graph=seeded_graph)
    assert len(paths) > 0, "Expected at least one risky multi-hop access path"

    # Find the specific path through CustomerSupportBot -> SQLQueryTool -> PII DB
    risky_path = next((p for p in paths if p["tool_name"] == "SQLQueryTool"), None)
    assert risky_path is not None, "Failed to detect risky path through SQLQueryTool"
    assert risky_path["agent_name"] == "CustomerSupportBot"
    assert risky_path["resource_name"] == "Customer PII & Credit Cards DB"
    assert risky_path["resource_classification"] == "confidential"
    assert risky_path["permission_id"] == "perm-002"
    assert risky_path["permission_status"] == "active"


def test_permission_revocation_removes_risky_path(seeded_graph):
    """Verify that revoking the risky permission removes the multi-hop attack path."""
    # 1. Confirm path exists initially
    initial_paths = trace_untrusted_confidential_paths(graph=seeded_graph)
    assert any(p["permission_id"] == "perm-002" for p in initial_paths)

    # 2. Execute mitigation: Revoke permission perm-002
    success = revoke_permission("perm-002", graph=seeded_graph)
    assert success is True, "Failed to revoke permission perm-002"

    # 3. Rerun multi-hop query and verify the path is gone
    updated_paths = trace_untrusted_confidential_paths(graph=seeded_graph)
    assert not any(p["permission_id"] == "perm-002" for p in updated_paths), (
        "Risky path still exists after permission revocation!"
    )
    assert len(updated_paths) == 0, "Expected 0 untrusted confidential paths after revoking perm-002"

    # 4. Restore permission and verify path reappears (idempotency / reversibility)
    restore_success = restore_permission("perm-002", graph=seeded_graph)
    assert restore_success is True
    restored_paths = trace_untrusted_confidential_paths(graph=seeded_graph)
    assert len(restored_paths) > 0


def test_incident_blast_radius_tracing(seeded_graph):
    """Verify tracing blast radius from a security incident event to exposed resources."""
    blast = trace_incident_blast_radius("evt-inject-01", graph=seeded_graph)
    assert len(blast) > 0, "Expected blast radius for evt-inject-01"

    exposed_resources = {b["exposed_resource"] for b in blast}
    assert "Customer PII & Credit Cards DB" in exposed_resources
