"""Tests real FalkorDB database connection and Cypher query execution."""

import pytest
from src.db import get_falkordb_client, get_graph, check_connection


def test_real_falkordb_ping():
    """Verify that a real FalkorDB connection can be established and responds to queries."""
    client = get_falkordb_client()
    assert client is not None

    graph = client.select_graph("test_conn_check")
    res = graph.query("RETURN 42 AS answer")
    assert len(res.result_set) == 1
    assert res.result_set[0][0] == 42

    # Clean up test graph
    graph.delete()


def test_healthcheck_function():
    """Verify that the check_connection helper accurately reports FalkorDB status."""
    assert check_connection() is True
