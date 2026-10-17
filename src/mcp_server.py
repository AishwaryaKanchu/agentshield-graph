"""Model Context Protocol (MCP) server for AgentShield Graph.

Exposes security graph investigation, multi-hop path analysis, blast radius
tracing, and synthetic permission remediation tools to AI agents using the
official Python MCP SDK.
"""

from typing import Dict, Any, List, Optional
from mcp.server.mcpserver import MCPServer
from src.security_graph import (
    trace_untrusted_confidential_paths,
    trace_incident_blast_radius,
    revoke_permission,
    restore_permission,
    get_entity_evidence,
    verify_path_exists,
)

# Initialize MCP Server instance
mcp_server = MCPServer("AgentShieldGraph")


@mcp_server.tool()
def find_multi_hop_paths(
    target_classification: str = "confidential",
) -> Dict[str, Any]:
    """Finds multi-hop access paths from low-trust or untrusted agents

    through tools to confidential or restricted resources.

    Args:
        target_classification: 'confidential', 'restricted', or 'all'.
    """
    valid_classes = {"confidential", "restricted", "all"}
    clean_target = target_classification.strip().lower()
    if clean_target not in valid_classes:
        return {
            "success": False,
            "error": f"Invalid classification '{target_classification}'. Must be one of: {sorted(list(valid_classes))}",
            "paths": [],
        }

    raw_paths = trace_untrusted_confidential_paths()
    if clean_target != "all":
        filtered_paths = [
            p for p in raw_paths if p.get("resource_classification", "").lower() == clean_target
        ]
    else:
        filtered_paths = raw_paths

    return {
        "success": True,
        "query_target": clean_target,
        "path_count": len(filtered_paths),
        "paths": filtered_paths,
        "risk_level": "CRITICAL" if len(filtered_paths) > 0 else "NONE",
    }


@mcp_server.tool()
def investigate_incident_blast_radius(incident_id: str) -> Dict[str, Any]:
    """Investigates a security incident event and traces its downstream

    blast radius to exposed tools and sensitive resources.

    Args:
        incident_id: The ID of the incident event (e.g., 'evt-inject-01').
    """
    clean_id = incident_id.strip()
    if not clean_id:
        return {"success": False, "error": "incident_id cannot be empty", "blast_radius": []}

    blast = trace_incident_blast_radius(clean_id)
    if not blast:
        # Check if the incident exists at all
        evidence = get_entity_evidence(clean_id)
        if not evidence.get("found"):
            return {
                "success": False,
                "error": f"Incident '{clean_id}' was not found in the security graph.",
                "blast_radius": [],
            }
        return {
            "success": True,
            "incident_id": clean_id,
            "blast_count": 0,
            "blast_radius": [],
            "risk_assessment": "LOW - No active paths to confidential resources found",
        }

    exposed_confidential = [b for b in blast if b.get("data_classification") in ["confidential", "restricted"]]

    return {
        "success": True,
        "incident_id": clean_id,
        "blast_count": len(blast),
        "blast_radius": blast,
        "confidential_exposure_count": len(exposed_confidential),
        "risk_assessment": "CRITICAL" if exposed_confidential else "MEDIUM",
        "recommended_action": "Revoke active tool permission connecting targeted agent to sensitive resource",
    }


@mcp_server.tool()
def get_graph_evidence(entity_id: str) -> Dict[str, Any]:
    """Retrieves verified graph evidence for a specific entity ID,

    including node labels, properties, and all incoming/outgoing relationships.

    Args:
        entity_id: The ID of the node (user, agent, tool, resource, or event).
    """
    clean_id = entity_id.strip()
    if not clean_id:
        return {"success": False, "error": "entity_id cannot be empty"}

    evidence = get_entity_evidence(clean_id)
    return {"success": evidence.get("found", False), "evidence": evidence}


@mcp_server.tool()
def revoke_permission_tool(permission_id: str) -> Dict[str, Any]:
    """Simulates containment remediation in the synthetic test environment

    by revoking a CAN_CALL permission between an agent and a tool.

    Args:
        permission_id: The ID of the permission to revoke (e.g., 'perm-002').
    """
    clean_id = permission_id.strip()
    if not clean_id:
        return {"success": False, "error": "permission_id cannot be empty"}

    success = revoke_permission(clean_id)
    return {
        "success": success,
        "permission_id": clean_id,
        "action": "REVOKE",
        "new_status": "revoked" if success else "unchanged",
        "message": (
            f"Permission '{clean_id}' successfully revoked."
            if success
            else f"Permission '{clean_id}' not found or already inactive."
        ),
    }


@mcp_server.tool()
def restore_permission_tool(permission_id: str) -> Dict[str, Any]:
    """Restores a revoked permission back to 'active' status in the synthetic

    test environment for testing and simulation reversibility.

    Args:
        permission_id: The ID of the permission to restore (e.g., 'perm-002').
    """
    clean_id = permission_id.strip()
    if not clean_id:
        return {"success": False, "error": "permission_id cannot be empty"}

    success = restore_permission(clean_id)
    return {
        "success": success,
        "permission_id": clean_id,
        "action": "RESTORE",
        "new_status": "active" if success else "unchanged",
        "message": (
            f"Permission '{clean_id}' successfully restored to active."
            if success
            else f"Permission '{clean_id}' not found."
        ),
    }


@mcp_server.tool()
def verify_remediation(permission_id: str) -> Dict[str, Any]:
    """Verifies whether an attack path still connects to confidential resources

    after a permission change. Re-queries the live FalkorDB graph.

    Args:
        permission_id: The permission ID that was modified.
    """
    clean_id = permission_id.strip()
    if not clean_id:
        return {"success": False, "error": "permission_id cannot be empty"}

    is_still_vulnerable = verify_path_exists(clean_id)
    return {
        "success": True,
        "permission_id": clean_id,
        "active_vulnerable_path_exists": is_still_vulnerable,
        "remediation_verified": not is_still_vulnerable,
        "status": "SECURE - Risky path removed" if not is_still_vulnerable else "VULNERABLE - Active path still detected",
    }


if __name__ == "__main__":
    import asyncio
    print("Starting AgentShield Graph MCP Server (stdio transport)...")
    mcp_server.run()
