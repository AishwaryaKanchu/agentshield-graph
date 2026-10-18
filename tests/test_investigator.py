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


def test_investigator_api_key_sanitization():
    """Verify that surrounding whitespace and accidental quotes are cleanly stripped."""
    inv1 = AgentShieldInvestigator(api_key='  "AIzaSyTestKey123"  ')
    assert inv1._api_key == "AIzaSyTestKey123"

    inv2 = AgentShieldInvestigator(api_key="  'AIzaSyTestKey456'  ")
    assert inv2._api_key == "AIzaSyTestKey456"


def test_sanitize_error_redacts_secrets():
    """Verify that error messages redact API keys and provide user-friendly messages."""
    from src.investigator import sanitize_error

    secret_key = "AIzaSyDummySecretKey1234567890abcdef"

    # Test raw exception containing API key in query param or message
    err1 = Exception(f"Request failed at https://generativelanguage.googleapis.com/v1beta/models?key={secret_key}")
    sanitized1 = sanitize_error(err1)
    assert secret_key not in sanitized1
    assert "[REDACTED]" in sanitized1

    # Test API key invalid error
    err2 = Exception(f"400 API_KEY_INVALID: Key {secret_key} is not valid.")
    sanitized2 = sanitize_error(err2)
    assert secret_key not in sanitized2
    assert "Invalid Gemini API Key" in sanitized2

    # Test quota exceeded
    err3 = Exception("429 RESOURCE_EXHAUSTED: Quota exceeded for GenerateContent.")
    sanitized3 = sanitize_error(err3)
    assert "Quota Exceeded" in sanitized3

    # Test model not found
    err4 = Exception("404 NOT_FOUND: models/nonexistent is not found.")
    sanitized4 = sanitize_error(err4)
    assert "Model Unavailable" in sanitized4


def test_investigator_fallback_captures_error(monkeypatch):
    """Verify that when Gemini throws an exception, investigator gracefully falls back and captures the error."""
    async def _run():
        from unittest.mock import AsyncMock, patch

        inv = AgentShieldInvestigator(api_key="test_key")
        assert inv.has_llm is True

        # Mock _execute_mcp_tool so FalkorDB is not required for this unit test
        async def mock_mcp(tool_name, args):
            return {"success": True, "blast_radius": [], "paths": []}

        monkeypatch.setattr(inv, "_execute_mcp_tool", mock_mcp)

        # Force _investigate_with_gemini to raise an API error
        async def mock_gemini_fail(*args, **kwargs):
            raise Exception("400 API_KEY_INVALID: API key not valid.")

        monkeypatch.setattr(inv, "_investigate_with_gemini", mock_gemini_fail)

        report = await inv.investigate("Investigate incident evt-inject-01")
        assert report is not None
        assert report.provider == "deterministic-fallback (LLM unavailable)"
        assert report.llm_verified is False
        assert report.error_message is not None
        assert "Invalid Gemini API Key" in report.error_message
        assert len(report.tool_calls) > 0

    asyncio.run(_run())


def test_investigator_gemini_success_flow(monkeypatch):
    """Verify that when Gemini succeeds, the report is marked as verified with parsed findings."""
    async def _run():
        inv = AgentShieldInvestigator(api_key="test_key", model="gemini-2.0-flash")
        assert inv.has_llm is True

        # Mock _execute_mcp_tool
        async def mock_mcp(tool_name, args):
            return {"success": True, "blast_radius": [], "paths": []}

        monkeypatch.setattr(inv, "_execute_mcp_tool", mock_mcp)

        # Mock successful Gemini response
        mock_response_text = (
            "[CONFIRMED GRAPH FINDING] Multi-hop access path detected through CustomerSupportBot.\n"
            "[POTENTIAL RISK] Untrusted user Alice could query sensitive database.\n"
            "[UNVERIFIED CONCLUSION] Host firewall exfiltration status requires server logs.\n"
        )

        class DummyModelResponse:
            text = mock_response_text

        class DummyClient:
            class aio:
                class models:
                    @staticmethod
                    async def generate_content(*args, **kwargs):
                        return DummyModelResponse()

        # Patch genai in _investigate_with_gemini
        import google.genai
        monkeypatch.setattr(google.genai, "Client", lambda **kwargs: DummyClient())

        report = await inv.investigate("Audit security posture of CustomerSupportBot")
        assert report is not None
        assert "Google Gemini" in report.provider
        assert report.llm_verified is True
        assert report.error_message is None
        assert any("CustomerSupportBot" in f for f in report.confirmed_findings)
        assert any("Alice" in r for r in report.potential_risks)
        assert any("firewall" in u.lower() for u in report.unverified_conclusions)

    asyncio.run(_run())


def test_verify_credentials_no_key():
    """Verify that verify_credentials cleanly handles missing API key."""
    async def _run():
        inv = AgentShieldInvestigator(api_key="")
        valid, msg = await inv.verify_credentials()
        assert valid is False
        assert "No API key" in msg

    asyncio.run(_run())


def test_verify_credentials_invalid_key():
    """Verify that verify_credentials handles invalid keys safely without leaking secrets."""
    async def _run():
        dummy_secret = "AIzaSyFakeKeyForTestVerification12345"
        inv = AgentShieldInvestigator(api_key=dummy_secret)
        valid, msg = await inv.verify_credentials()
        assert valid is False
        # Ensure secret key is NEVER leaked in the output message
        assert dummy_secret not in msg
        assert ("Invalid Gemini API Key" in msg or "API error" in msg)

    asyncio.run(_run())



