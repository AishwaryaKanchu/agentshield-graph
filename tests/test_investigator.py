"""Automated tests for AgentShield AI Security Investigator Agent."""

import asyncio
import pytest
from src.init_db import init_database
from src.investigator import AgentShieldInvestigator


@pytest.fixture(scope="module")
def setup_investigator_graph():
    """Ensure a clean test graph is initialized for investigator tests."""
    g = init_database(graph_name="agentshield_investigator_test", clear_existing=True)
    yield g
    try:
        g.delete()
    except Exception:
        pass


def test_investigator_no_api_key_fallback():
    """Verify that investigator runs end-to-end without requiring an API key."""
    async def _run():
        investigator = AgentShieldInvestigator(api_key="")
        assert investigator.has_llm is False

        report = await investigator.investigate("Audit all multi-hop paths to confidential data")
        assert report is not None
        assert report.provider == "deterministic-fallback"
        assert len(report.tool_calls) > 0
        assert len(report.confirmed_findings) > 0
        assert len(report.potential_risks) > 0
        assert len(report.unverified_conclusions) > 0
    asyncio.run(_run())


def test_investigator_tool_selection_incident():
    """Verify that queries mentioning an incident select the blast radius tool."""
    async def _run():
        investigator = AgentShieldInvestigator(api_key="")
        report = await investigator.investigate("Investigate incident evt-inject-01 and trace its blast radius")

        selected_tools = [tc["tool"] for tc in report.tool_calls]
        assert "investigate_incident_blast_radius" in selected_tools
        assert any("evt-inject-01" in f for f in report.confirmed_findings)
    asyncio.run(_run())


def test_investigator_tool_selection_multi_hop():
    """Verify that queries asking about untrusted paths select find_multi_hop_paths."""
    async def _run():
        investigator = AgentShieldInvestigator(api_key="")
        report = await investigator.investigate("Find any untrusted access paths to confidential resources")

        selected_tools = [tc["tool"] for tc in report.tool_calls]
        assert "find_multi_hop_paths" in selected_tools
        assert any("SQLQueryTool" in f for f in report.confirmed_findings)
    asyncio.run(_run())


def test_investigator_evidence_distinction():
    """Verify that confirmed findings, potential risks, and unverified conclusions

    are clearly distinguished and backed by evidence.
    """
    async def _run():
        investigator = AgentShieldInvestigator(api_key="")
        report = await investigator.investigate("Audit security posture of CustomerSupportBot")

        # Confirmed findings must contain graph terms
        assert any("[CONFIRMED GRAPH FINDING]" in f or "CustomerSupportBot" in f for f in report.confirmed_findings)

        # Potential risks must highlight exploitation scenarios
        assert any("exfiltration" in r.lower() or "injection" in r.lower() for r in report.potential_risks)

        # Unverified conclusions must explain telemetry boundaries
        assert any("external" in u.lower() or "log" in u.lower() for u in report.unverified_conclusions)
    asyncio.run(_run())


def test_investigator_remediation_and_verification():
    """Verify that investigator can execute remediation AND verify that

    the graph query confirms the attack path was removed.
    """
    async def _run():
        from src.security_graph import restore_permission
        investigator = AgentShieldInvestigator(api_key="")

        # Perform investigation with auto-remediation
        report = await investigator.investigate(
            "Remediate and isolate the risky permission connecting CustomerSupportBot to the database",
            auto_remediate=True,
        )

        assert len(report.remediations) > 0
        rem = report.remediations[0]
        assert rem["permission_id"] == "perm-002"
        assert rem["revoked"] is True
        assert rem["verified"] is True  # Verified via re-query

        selected_tools = [tc["tool"] for tc in report.tool_calls]
        assert "revoke_permission_tool" in selected_tools
        assert "verify_remediation" in selected_tools

        # Restore permission for test idempotency
        restore_permission("perm-002")
    asyncio.run(_run())


def test_investigator_api_key_loading(monkeypatch):
    """Verify that investigator correctly resolves api_key argument, GEMINI_API_KEY, and GOOGLE_API_KEY."""
    import os
    # 1. Direct key
    inv_direct = AgentShieldInvestigator(api_key="direct_key")
    assert inv_direct.has_llm is True

    # 2. GOOGLE_API_KEY env fallback
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("GOOGLE_API_KEY", "google_test_key")
    inv_google = AgentShieldInvestigator(api_key="")
    assert inv_google.has_llm is True

    # 3. Empty env
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("GOOGLE_API_KEY", "")
    inv_none = AgentShieldInvestigator(api_key="")
    assert inv_none.has_llm is False

