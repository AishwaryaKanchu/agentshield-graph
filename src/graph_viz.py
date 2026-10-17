"""Interactive graph visualization generator for AgentShield Graph Command Center."""

from typing import Optional, Set, Tuple
from pyvis.network import Network
from src.db import get_graph
from src.security_graph import trace_untrusted_confidential_paths

# Cybersecurity color palette
PALETTE = {
    "User": {"color": "#AB47BC", "shape": "dot", "size": 24},
    "User_Untrusted": {"color": "#FF7043", "shape": "dot", "size": 26},
    "Agent": {"color": "#29B6F6", "shape": "box", "size": 25},
    "Agent_LowTrust": {"color": "#EC407A", "shape": "box", "size": 26},
    "Tool": {"color": "#FFA726", "shape": "diamond", "size": 25},
    "Tool_Critical": {"color": "#EF5350", "shape": "diamond", "size": 28},
    "Resource_Public": {"color": "#66BB6A", "shape": "database", "size": 25},
    "Resource_Confidential": {"color": "#E53935", "shape": "database", "size": 28},
    "Resource_Restricted": {"color": "#D32F2F", "shape": "database", "size": 28},
    "SecurityEvent": {"color": "#FF1744", "shape": "star", "size": 32},
}


def generate_graph_html(graph=None, highlight_risks: bool = True) -> str:
    """Queries FalkorDB and generates a styled PyVis HTML graph visualization

    with dark cybersecurity theme and highlighted attack paths.
    """
    g = graph or get_graph()

    # Find risky edges to highlight
    risky_edges: Set[Tuple[str, str]] = set()
    if highlight_risks:
        untrusted_paths = trace_untrusted_confidential_paths(graph=g)
        for p in untrusted_paths:
            risky_edges.add((p["user_id"], p["agent_id"]))
            risky_edges.add((p["agent_id"], p["tool_id"]))
            risky_edges.add((p["tool_id"], p["resource_id"]))

    # Initialize PyVis network
    net = Network(
        height="520px",
        width="100%",
        bgcolor="#0e1117",
        font_color="#FFFFFF",
        directed=True,
    )

    # Physics configuration for clean layout
    net.set_options("""
    {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -60,
          "centralGravity": 0.015,
          "springLength": 110,
          "springConstant": 0.08
        },
        "maxVelocity": 40,
        "solver": "forceAtlas2Based",
        "timestep": 0.35,
        "stabilization": {"iterations": 150}
      },
      "edges": {
        "smooth": {"type": "continuous"}
      }
    }
    """)

    # 1. Fetch and add nodes
    node_query = "MATCH (n) RETURN labels(n)[0] AS label, properties(n) AS props"
    nodes = g.query(node_query).result_set

    for row in nodes:
        label = row[0]
        props = row[1]
        node_id = props.get("id", str(props.get("name", "unknown")))
        node_name = props.get("name", node_id)

        # Style resolution
        style_key = label
        if label == "User" and props.get("role") == "external":
            style_key = "User_Untrusted"
        elif label == "Agent" and props.get("trust_level") == "low":
            style_key = "Agent_LowTrust"
        elif label == "Tool" and props.get("risk_level") == "critical":
            style_key = "Tool_Critical"
        elif label == "Resource":
            classification = props.get("classification", "public")
            if classification == "confidential":
                style_key = "Resource_Confidential"
            elif classification == "restricted":
                style_key = "Resource_Restricted"
            else:
                style_key = "Resource_Public"

        cfg = PALETTE.get(style_key, {"color": "#9E9E9E", "shape": "dot", "size": 20})

        # Tooltip text
        title_lines = [f"<b>{label}:</b> {node_name}", f"<b>ID:</b> {node_id}"]
        for k, v in props.items():
            if k not in ["name", "id"]:
                title_lines.append(f"<b>{k}:</b> {v}")
        tooltip = "<br>".join(title_lines)

        net.add_node(
            node_id,
            label=f"{node_name}",
            title=tooltip,
            color=cfg["color"],
            shape=cfg["shape"],
            size=cfg["size"],
            borderWidth=2,
            shadow=True,
        )

    # 2. Fetch and add relationships
    rel_query = """
    MATCH (a)-[r]->(b)
    RETURN properties(a).id AS src, type(r) AS rel_type, properties(r) AS props, properties(b).id AS dst
    """
    rels = g.query(rel_query).result_set

    for row in rels:
        src = row[0]
        rel_type = row[1]
        props = row[2]
        dst = row[3]

        if not src or not dst:
            continue

        is_risky = (src, dst) in risky_edges
        status = props.get("status", "active")
        is_revoked = status == "revoked"

        if is_revoked:
            edge_color = "#555555"
            edge_width = 1
            dashes = True
            label_text = f"{rel_type} (REVOKED)"
        elif is_risky:
            edge_color = "#FF1744"
            edge_width = 3.5
            dashes = False
            label_text = f"{rel_type} ⚠️"
        else:
            edge_color = "#455A64"
            edge_width = 1.5
            dashes = False
            label_text = rel_type

        title_tip = f"<b>{rel_type}</b><br>From: {src}<br>To: {dst}"
        if props:
            title_tip += "<br>" + "<br>".join([f"{k}: {v}" for k, v in props.items()])

        net.add_edge(
            src,
            dst,
            title=title_tip,
            label=label_text,
            color=edge_color,
            width=edge_width,
            dashes=dashes,
            arrows="to",
        )

    return net.generate_html()
