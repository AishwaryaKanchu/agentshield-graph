"""Security graph query and remediation operations for AgentShield Graph."""

from typing import List, Dict, Any, Optional
from src.db import get_graph


def trace_untrusted_confidential_paths(graph=None) -> List[Dict[str, Any]]:
    """Executes a real Cypher query tracing multi-hop access paths from untrusted

    or low-trust agents through tools to confidential/restricted resources.

    Hop 1: (User)-[:INTERACTS_WITH]->(Agent)
    Hop 2: (Agent)-[:CAN_CALL {status: 'active'}]->(Tool)
    Hop 3: (Tool)-[:ACCESSES]->(Resource {classification: confidential|restricted})
    """
    g = graph or get_graph()
    query = """
    MATCH (u:User)-[i:INTERACTS_WITH]->(a:Agent)-[p:CAN_CALL]->(t:Tool)-[acc:ACCESSES]->(r:Resource)
    WHERE a.trust_level IN ['untrusted', 'low']
      AND r.classification IN ['confidential', 'restricted']
      AND p.status = 'active'
    RETURN u.id AS user_id,
           u.name AS user_name,
           a.id AS agent_id,
           a.name AS agent_name,
           a.trust_level AS agent_trust,
           p.permission_id AS permission_id,
           p.status AS permission_status,
           t.id AS tool_id,
           t.name AS tool_name,
           t.risk_level AS tool_risk,
           r.id AS resource_id,
           r.name AS resource_name,
           r.classification AS resource_classification
    """
    res = g.query(query)
    paths = []
    for row in res.result_set:
        paths.append({
            "user_id": row[0],
            "user_name": row[1],
            "agent_id": row[2],
            "agent_name": row[3],
            "agent_trust": row[4],
            "permission_id": row[5],
            "permission_status": row[6],
            "tool_id": row[7],
            "tool_name": row[8],
            "tool_risk": row[9],
            "resource_id": row[10],
            "resource_name": row[11],
            "resource_classification": row[12],
        })
    return paths


def trace_incident_blast_radius(incident_id: str, graph=None) -> List[Dict[str, Any]]:
    """Traces the potential blast radius of an active security incident:

    (SecurityEvent)-[:DETECTED_ON]->(Agent)-[:CAN_CALL]->(Tool)-[:ACCESSES]->(Resource)
    """
    g = graph or get_graph()
    query = """
    MATCH (e:SecurityEvent {id: $incident_id})-[:DETECTED_ON]->(a:Agent)-[p:CAN_CALL {status: 'active'}]->(t:Tool)-[acc:ACCESSES]->(r:Resource)
    RETURN e.id AS event_id,
           e.type AS event_type,
           e.severity AS severity,
           a.name AS targeted_agent,
           t.name AS vulnerable_tool,
           r.name AS exposed_resource,
           r.classification AS data_classification
    """
    res = g.query(query, {"incident_id": incident_id})
    blast = []
    for row in res.result_set:
        blast.append({
            "event_id": row[0],
            "event_type": row[1],
            "severity": row[2],
            "targeted_agent": row[3],
            "vulnerable_tool": row[4],
            "exposed_resource": row[5],
            "data_classification": row[6],
        })
    return blast


def revoke_permission(permission_id: str, graph=None) -> bool:
    """Simulates/executes policy remediation by updating a CAN_CALL permission

    status from 'active' to 'revoked'.
    """
    g = graph or get_graph()
    query = """
    MATCH ()-[p:CAN_CALL {permission_id: $perm_id}]->()
    SET p.status = 'revoked'
    RETURN count(p) AS updated_count
    """
    res = g.query(query, {"perm_id": permission_id})
    return res.result_set[0][0] > 0


def restore_permission(permission_id: str, graph=None) -> bool:
    """Restores a revoked permission back to 'active'."""
    g = graph or get_graph()
    query = """
    MATCH ()-[p:CAN_CALL {permission_id: $perm_id}]->()
    SET p.status = 'active'
    RETURN count(p) AS updated_count
    """
    res = g.query(query, {"perm_id": permission_id})
    return res.result_set[0][0] > 0


def get_all_agents(graph=None) -> List[Dict[str, Any]]:
    """Retrieves all agents and their security profiles."""
    g = graph or get_graph()
    res = g.query("MATCH (a:Agent) RETURN a.id, a.name, a.role, a.trust_level, a.status ORDER BY a.name")
    return [
        {"id": row[0], "name": row[1], "role": row[2], "trust_level": row[3], "status": row[4]}
        for row in res.result_set
    ]


def get_entity_evidence(entity_id: str, graph=None) -> Dict[str, Any]:
    """Retrieves verified graph evidence for a specific entity ID,

    including its node properties, incoming relationships, and outgoing relationships.
    """
    g = graph or get_graph()
    node_query = "MATCH (n {id: $entity_id}) RETURN labels(n)[0] AS label, properties(n) AS props"
    node_res = g.query(node_query, {"entity_id": entity_id})
    if not node_res.result_set:
        return {"found": False, "entity_id": entity_id, "error": f"No entity found with id '{entity_id}'"}

    label = node_res.result_set[0][0]
    props = node_res.result_set[0][1]

    # Inbound edges
    in_query = """
    MATCH (src)-[r]->(n {id: $entity_id})
    RETURN type(r) AS rel_type, properties(r) AS rel_props, labels(src)[0] AS src_label, properties(src) AS src_props
    """
    in_res = g.query(in_query, {"entity_id": entity_id})
    incoming = [
        {"relation": row[0], "properties": row[1], "source_label": row[2], "source": row[3]}
        for row in in_res.result_set
    ]

    # Outbound edges
    out_query = """
    MATCH (n {id: $entity_id})-[r]->(dst)
    RETURN type(r) AS rel_type, properties(r) AS rel_props, labels(dst)[0] AS dst_label, properties(dst) AS dst_props
    """
    out_res = g.query(out_query, {"entity_id": entity_id})
    outgoing = [
        {"relation": row[0], "properties": row[1], "target_label": row[2], "target": row[3]}
        for row in out_res.result_set
    ]

    return {
        "found": True,
        "entity_id": entity_id,
        "label": label,
        "properties": props,
        "incoming_relations": incoming,
        "outgoing_relations": outgoing,
    }


def verify_path_exists(permission_id: str, graph=None) -> bool:
    """Verifies whether an active path through a specific permission still exists

    and connects to a confidential or restricted resource.
    """
    g = graph or get_graph()
    query = """
    MATCH ()-[p:CAN_CALL {permission_id: $perm_id, status: 'active'}]->(t:Tool)-[:ACCESSES]->(r:Resource)
    WHERE r.classification IN ['confidential', 'restricted']
    RETURN count(p) AS active_paths
    """
    res = g.query(query, {"perm_id": permission_id})
    return res.result_set[0][0] > 0

