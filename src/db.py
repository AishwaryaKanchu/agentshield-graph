
"""FalkorDB connection and graph management for AgentShield Graph."""

import os
from typing import Optional

import streamlit as st
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()


def get_setting(key: str, default=None):
    """Read configuration from environment variables or Streamlit Secrets."""
    value = os.getenv(key)

    if value is not None and value != "":
        return value

    try:
        return st.secrets.get(key, default)
    except Exception:
        return default


DEFAULT_HOST = get_setting("FALKORDB_HOST", "localhost")
DEFAULT_PORT = int(get_setting("FALKORDB_PORT", "6379"))
DEFAULT_GRAPH = get_setting("FALKORDB_GRAPH", "agentshield")
DEFAULT_USERNAME = get_setting("FALKORDB_USERNAME")
DEFAULT_PASSWORD = get_setting("FALKORDB_PASSWORD")


def get_falkordb_client(
    host: Optional[str] = None,
    port: Optional[int] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> FalkorDB:
    """Connect to the FalkorDB instance."""
    use_tls = str(get_setting("FALKORDB_TLS", "false")).lower() == "true"

    return FalkorDB(
        host=host or DEFAULT_HOST,
        port=port or DEFAULT_PORT,
        username=username or DEFAULT_USERNAME,
        password=password or DEFAULT_PASSWORD,
        ssl=use_tls,
    )


def get_graph(
    graph_name: Optional[str] = None,
    client: Optional[FalkorDB] = None,
):
    """Retrieve or create a graph reference in FalkorDB."""
    falkor_client = client or get_falkordb_client()
    target_graph = graph_name or DEFAULT_GRAPH
    return falkor_client.select_graph(target_graph)


def check_connection(client: Optional[FalkorDB] = None) -> bool:
    """Check whether FalkorDB is reachable and responsive."""
    try:
        falkor_client = client or get_falkordb_client()
        temp_graph = falkor_client.select_graph("__healthcheck__")
        res = temp_graph.query("RETURN 1 AS ping")
        temp_graph.delete()
        return len(res.result_set) == 1 and res.result_set[0][0] == 1
    except Exception:
        return False
