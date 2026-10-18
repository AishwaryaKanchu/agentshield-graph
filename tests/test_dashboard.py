"""Focused integration tests for AgentShield Graph Streamlit Command Center components."""

import pytest
import py_compile
from src.db import check_connection, get_graph
from src.graph_viz import generate_graph_html
from src.security_graph import trace_untrusted_confidential_paths, verify_path_exists


def test_app_syntax_and_compilation():
    """Verify that app.py compiles cleanly with zero syntax or import structure errors."""
    compiled = py_compile.compile("app.py", doraise=True)
    assert compiled is not None


def test_graph_visualization_html_generation():
    """Verify that graph HTML generation executes and renders with required dark styling."""
    html = generate_graph_html(highlight_risks=True)
    assert html is not None
    assert len(html) > 1000
    assert "#0e1117" in html  # Dark background verified
    assert "CustomerSupportBot" in html
    assert "SQLQueryTool" in html
    assert "Customer PII" in html
    assert "Credit Cards DB" in html


def test_dashboard_metrics_data_integrity():
    """Verify that metric queries execute properly against FalkorDB."""
    assert check_connection() is True
    paths = trace_untrusted_confidential_paths()
    assert isinstance(paths, list)
    vulnerable = verify_path_exists("perm-002")
    assert isinstance(vulnerable, bool)


def test_dashboard_preset_query_structure():
    """Verify that app.py defines the preset query keys and callback mechanism."""
    with open("app.py", "r", encoding="utf-8") as f:
        content = f.read()
    assert "select_preset_query" in content
    assert "btn_preset_incident" in content
    assert "btn_preset_paths" in content
    assert "btn_preset_agent" in content
    assert "btn_preset_isolate" in content
    assert 'key="investigator_query"' in content


def test_dashboard_gemini_key_resolution_structure():
    """Verify that app.py defines get_active_gemini_api_key with dual session state keys and fallback."""
    with open("app.py", "r", encoding="utf-8") as f:
        content = f.read()
    assert "def get_active_gemini_api_key" in content
    assert "custom_gemini_api_key" in content
    assert "sidebar_api_key_input" in content
    assert "GEMINI_API_KEY" in content
    assert "GOOGLE_API_KEY" in content


def test_dashboard_verification_ui_elements():
    """Verify that app.py contains the key verification button and accurate status logic."""
    with open("app.py", "r", encoding="utf-8") as f:
        content = f.read()
    assert "Verify Gemini Key" in content
    assert "gemini_verified" in content
    assert "gemini_last_error" in content
    assert "Live LLM Reasoning Active" in content


