"""Automated tests for AgentShield Graph MCP tools and server."""

import pytest
import asyncio
from src.init_db import init_database
from src.mcp_server import mcp_server


@pytest.fixture(scope="module")
def setup_mcp_test_graph():
    """Ensure a clean test graph is initialized for MCP tool testing."""
    g = init_database(graph_name="agentshield_mcp_test", clear_existing=True)
    yield g
    try:
        g.delete()
    except Exception:
        pass


def test_mcp_tool_listing():
    """Verify that all required security tools are registered on the MCP server."""
    async def _run():
        tools = await mcp_server.list_tools()
        tool_names = {t.name for t in tools}
        expected_tools = {
            "find_multi_hop_paths",
            "investigate_incident_blast_radius",
            "get_graph_evidence",
            "revoke_permission_tool",
            "restore_permission_tool",
            "verify_remediation",
        }
        assert expected_tools.issubset(tool_names), f"Missing MCP tools: {expected_tools - tool_names}"
    asyncio.run(_run())


def test_mcp_find_multi_hop_paths():
    """Test find_multi_hop_paths MCP tool execution against FalkorDB."""
    async def _run():
        # Test valid call
        res = await mcp_server.call_tool("find_multi_hop_paths", {"target_classification": "confidential"})
        data = res.structured_content.get("result", {})
        assert data.get("success") is True
        assert data.get("path_count") > 0
        assert any(p["tool_name"] == "SQLQueryTool" for p in data.get("paths", []))

        # Test invalid classification validation
        err_res = await mcp_server.call_tool("find_multi_hop_paths", {"target_classification": "invalid_class"})
        err_data = err_res.structured_content.get("result", {})
        assert err_data.get("success") is False
        assert "Invalid classification" in err_data.get("error", "")
    asyncio.run(_run())


def test_mcp_investigate_incident_blast_radius():
    """Test incident blast radius investigation via MCP tool."""
    async def _run():
        res = await mcp_server.call_tool("investigate_incident_blast_radius", {"incident_id": "evt-inject-01"})
        data = res.structured_content.get("result", {})
        assert data.get("success") is True
        assert data.get("blast_count") > 0
        assert data.get("risk_assessment") == "CRITICAL"
        exposed = [b["exposed_resource"] for b in data.get("blast_radius", [])]
        assert "Customer PII & Credit Cards DB" in exposed
    asyncio.run(_run())


def test_mcp_get_graph_evidence():
    """Test retrieving verified graph evidence for an agent node."""
    async def _run():
        res = await mcp_server.call_tool("get_graph_evidence", {"entity_id": "agent-support"})
        data = res.structured_content.get("result", {})
        assert data.get("success") is True
        evidence = data.get("evidence", {})
        assert evidence.get("label") == "Agent"
        assert evidence.get("properties", {}).get("name") == "CustomerSupportBot"
        assert len(evidence.get("outgoing_relations", [])) > 0
    asyncio.run(_run())


def test_mcp_permission_remediation_and_verification():
    """Test end-to-end remediation lifecycle via MCP tools:

    Revoke -> Verify Remediation -> Restore.
    """
    async def _run():
        # 1. Revoke permission perm-002
        revoke_res = await mcp_server.call_tool("revoke_permission_tool", {"permission_id": "perm-002"})
        rev_data = revoke_res.structured_content.get("result", {})
        assert rev_data.get("success") is True
        assert rev_data.get("new_status") == "revoked"

        # 2. Verify remediation via real Cypher re-query
        verify_res = await mcp_server.call_tool("verify_remediation", {"permission_id": "perm-002"})
        ver_data = verify_res.structured_content.get("result", {})
        assert ver_data.get("success") is True
        assert ver_data.get("remediation_verified") is True
        assert ver_data.get("active_vulnerable_path_exists") is False

        # 3. Restore permission perm-002 for test reversibility
        restore_res = await mcp_server.call_tool("restore_permission_tool", {"permission_id": "perm-002"})
        rst_data = restore_res.structured_content.get("result", {})
        assert rst_data.get("success") is True
        assert rst_data.get("new_status") == "active"
    asyncio.run(_run())
