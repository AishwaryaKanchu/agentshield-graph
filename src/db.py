"""FalkorDB connection and graph management for AgentShield Graph."""

import os
from typing import Optional
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

DEFAULT_HOST = os.getenv("FALKORDB_HOST", "localhost")
DEFAULT_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
DEFAULT_GRAPH = os.getenv("FALKORDB_GRAPH", "agentshield")
DEFAULT_USERNAME = os.getenv("FALKORDB_USERNAME", None)
DEFAULT_PASSWORD = os.getenv("FALKORDB_PASSWORD", None)


def get_falkordb_client(
    host: Optional[str] = None,
    port: Optional[int] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> FalkorDB:
    """Connect to the FalkorDB instance."""
    return FalkorDB(
        host=host or DEFAULT_HOST,
        port=port or DEFAULT_PORT,
        username=username or DEFAULT_USERNAME,
        password=password or DEFAULT_PASSWORD,
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
