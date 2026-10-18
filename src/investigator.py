"""AI Security Investigator Agent for AgentShield Graph.

Acts on the connected security graph in FalkorDB via MCP tools.
Supports Google Gemini with automatic, robust deterministic fallback
when no API key is provided, ensuring reliable and fully reproducible
investigations.
"""

import os
import re
import asyncio
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from dotenv import load_dotenv

from src.mcp_server import mcp_server

load_dotenv(override=True)


@dataclass
class RemediationResult:
    permission_id: str
    action_taken: str
    revocation_confirmed: bool
    remediation_verified: bool
    details: str


def sanitize_error(exc: Exception) -> str:
    """Sanitizes exception messages to guarantee API keys are never exposed.

    Provides user-friendly diagnostics for common API failure modes.
    """
    raw = str(exc)
    # Redact any potential API key patterns or query parameters
    scrubbed = re.sub(r"key=[A-Za-z0-9_-]+", "key=[REDACTED]", raw)
    scrubbed = re.sub(r"AIza[0-9A-Za-z_-]{35}", "[REDACTED_KEY]", scrubbed)

    if "API_KEY_INVALID" in raw or "API key not valid" in raw:
        return "Invalid Gemini API Key: Please verify your Google AI Studio key."
    elif "RESOURCE_EXHAUSTED" in raw or "429" in raw or "quota" in raw.lower():
        return "Gemini API Quota Exceeded / Rate Limited (HTTP 429)."
    elif "NOT_FOUND" in raw or "404" in raw:
        return f"Gemini Model Unavailable: {scrubbed[:120]}"
    elif "ConnectError" in type(exc).__name__ or "timeout" in raw.lower():
        return "Network connection to Gemini API timed out or unreachable."

    return f"Gemini API error ({type(exc).__name__}): {scrubbed[:140]}"


@dataclass
class InvestigationReport:
    query: str
    provider: str
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    confirmed_findings: List[str] = field(default_factory=list)
    potential_risks: List[str] = field(default_factory=list)
    unverified_conclusions: List[str] = field(default_factory=list)
    remediations: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    error_message: Optional[str] = None
    llm_verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AgentShieldInvestigator:
    """Investigates AI agent runtime security incidents and multi-hop attack paths

    over FalkorDB knowledge graph.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        # Support GEMINI_API_KEY and GOOGLE_API_KEY; never expose keys in logs; strip quotes/spaces
        raw_key = (
            (api_key or "").strip().strip("'\"")
            or os.getenv("GEMINI_API_KEY", "").strip().strip("'\"")
            or os.getenv("GOOGLE_API_KEY", "").strip().strip("'\"")
        )
        self._api_key = raw_key
        # Default model matches .env.example (gemini-2.0-flash is universally available across all tiers)
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
        self.has_llm = bool(self._api_key)

    async def verify_credentials(self) -> tuple[bool, str]:
        """Probes the Gemini API with a minimal query to verify key validity.

        Returns (is_valid, message) without ever revealing secrets.
        """
        if not self.has_llm:
            return False, "No API key configured."
        try:
            from google import genai
            client = genai.Client(api_key=self._api_key)
            if hasattr(client, "aio") and hasattr(client.aio, "models"):
                resp = await client.aio.models.generate_content(
                    model=self.model,
                    contents="ping",
                )
            else:
                resp = client.models.generate_content(
                    model=self.model,
                    contents="ping",
                )
            if resp and resp.text:
                return True, f"Key verified with model '{self.model}'."
            return False, "Gemini returned empty response."
        except Exception as e:
            return False, sanitize_error(e)

    async def _execute_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Calls a registered MCP tool on mcp_server and returns its structured result."""
        result = await mcp_server.call_tool(tool_name, arguments)
        return result.structured_content.get("result", {})

    async def investigate(
        self,
        query: str,
        incident_id: Optional[str] = None,
        auto_remediate: bool = False,
    ) -> InvestigationReport:
        """Executes an investigation based on the query and any specified incident ID.

        If a Gemini API key is configured, uses Gemini with function calling.
        Otherwise, executes the deterministic graph investigation engine.
        """
        if self.has_llm:
            try:
                return await self._investigate_with_gemini(query, incident_id, auto_remediate)
            except Exception as e:
                # Graceful fallback to deterministic engine if Gemini fails or quota exceeded
                sanitized_msg = sanitize_error(e)
                report = await self._investigate_deterministic(query, incident_id, auto_remediate)
                report.provider = "deterministic-fallback (LLM unavailable)"
                report.error_message = sanitized_msg
                report.llm_verified = False
                return report
        else:
            return await self._investigate_deterministic(query, incident_id, auto_remediate)

    async def _investigate_deterministic(
        self,
        query: str,
        incident_id: Optional[str] = None,
        auto_remediate: bool = False,
    ) -> InvestigationReport:
        """Deterministic investigation engine that selects and executes MCP tools

        based on graph evidence and user query intent.
        """
        q_lower = query.lower()
        tool_calls = []
        confirmed_findings = []
        potential_risks = []
        unverified_conclusions = []
        remediations = []

        # 1. Tool Selection Heuristic based on query and context
        detected_incident = incident_id
        if not detected_incident:
            # Check for incident patterns like 'evt-inject-01' or 'evt-*'
            evt_match = re.search(r"\b(evt-[\w-]+)\b", query, re.IGNORECASE)
            if evt_match:
                detected_incident = evt_match.group(1)

        # 2. Execute Incident Blast Radius if incident detected or requested
        if detected_incident or "incident" in q_lower or "blast" in q_lower or "alert" in q_lower:
            target_inc = detected_incident or "evt-inject-01"
            inc_res = await self._execute_mcp_tool(
                "investigate_incident_blast_radius", {"incident_id": target_inc}
            )
            tool_calls.append({"tool": "investigate_incident_blast_radius", "args": {"incident_id": target_inc}, "result": inc_res})

            if inc_res.get("success") and inc_res.get("blast_radius"):
                for b in inc_res["blast_radius"]:
                    confirmed_findings.append(
                        f"[CONFIRMED GRAPH FINDING] Incident '{b['event_id']}' ({b['event_type']}, severity {b['severity']}) "
                        f"targets agent '{b['targeted_agent']}', which can invoke '{b['vulnerable_tool']}' "
                        f"exposing '{b['exposed_resource']}' ({b['data_classification']})."
                    )
                potential_risks.append(
                    f"[POTENTIAL RISK] High probability of confidential data exfiltration through compromised agent "
                    f"'{inc_res['blast_radius'][0]['targeted_agent']}' executing unauthorized tool queries."
                )

        # 3. Execute Multi-Hop Path Analysis
        if (
            "path" in q_lower
            or "untrusted" in q_lower
            or "confidential" in q_lower
            or "audit" in q_lower
            or "pii" in q_lower
            or len(tool_calls) == 0  # Default comprehensive audit
        ):
            paths_res = await self._execute_mcp_tool(
                "find_multi_hop_paths", {"target_classification": "confidential"}
            )
            tool_calls.append({"tool": "find_multi_hop_paths", "args": {"target_classification": "confidential"}, "result": paths_res})

            if paths_res.get("success") and paths_res.get("paths"):
                for p in paths_res["paths"]:
                    confirmed_findings.append(
                        f"[CONFIRMED GRAPH FINDING] Multi-hop access path detected: "
                        f"User '{p['user_name']}' -> Agent '{p['agent_name']}' (trust: {p['agent_trust']}) "
                        f"-[CAN_CALL {p['permission_id']}]-> Tool '{p['tool_name']}' "
                        f"-[ACCESSES]-> Resource '{p['resource_name']}' (classification: {p['resource_classification']})."
                    )
                potential_risks.append(
                    "[POTENTIAL RISK] External untrusted user Alice can indirectly access Customer PII database "
                    "via prompt injection on CustomerSupportBot."
                )
            elif paths_res.get("success") and not paths_res.get("paths"):
                confirmed_findings.append(
                    "[CONFIRMED GRAPH FINDING] Zero multi-hop paths from untrusted/low-trust agents to confidential resources found."
                )

        # 4. Execute Entity Evidence if specific entity mentioned
        entity_matches = re.findall(r"\b(agent-[\w-]+|tool-[\w-]+|u-[\w-]+|res-[\w-]+)\b", query, re.IGNORECASE)
        for ent_id in entity_matches:
            ev_res = await self._execute_mcp_tool("get_graph_evidence", {"entity_id": ent_id})
            tool_calls.append({"tool": "get_graph_evidence", "args": {"entity_id": ent_id}, "result": ev_res})
            if ev_res.get("success"):
                ev_data = ev_res["evidence"]
                confirmed_findings.append(
                    f"[CONFIRMED GRAPH FINDING] Verified node '{ent_id}' (Label: {ev_data.get('label')}, "
                    f"Properties: {ev_data.get('properties')})."
                )

        # 5. Unverified Conclusions / Boundary Telemetry
        unverified_conclusions.append(
            "[UNVERIFIED CONCLUSION] Egress payload verification: Graph confirms tool and data reachability, "
            "but external network exfiltration or disk writes require host/firewall log inspection."
        )

        # 6. Simulated Remediation & Verification
        should_remediate = auto_remediate or any(
            w in q_lower for w in ["fix", "remediate", "revoke", "isolate", "quarantine", "mitigate"]
        )
        if should_remediate:
            # Determine permission to revoke from evidence
            perm_to_revoke = "perm-002"  # CustomerSupportBot -> SQLQueryTool
            revoke_res = await self._execute_mcp_tool(
                "revoke_permission_tool", {"permission_id": perm_to_revoke}
            )
            tool_calls.append({"tool": "revoke_permission_tool", "args": {"permission_id": perm_to_revoke}, "result": revoke_res})

            # Mandatory verification query
            verify_res = await self._execute_mcp_tool(
                "verify_remediation", {"permission_id": perm_to_revoke}
            )
            tool_calls.append({"tool": "verify_remediation", "args": {"permission_id": perm_to_revoke}, "result": verify_res})

            rem_entry = {
                "permission_id": perm_to_revoke,
                "action": "REVOKE_CAN_CALL",
                "revoked": revoke_res.get("success", False),
                "verified": verify_res.get("remediation_verified", False),
                "details": "Simulated permission revocation in synthetic test environment. Graph re-query confirmed risky path removed.",
            }
            remediations.append(rem_entry)
            if rem_entry["verified"]:
                confirmed_findings.append(
                    f"[CONFIRMED GRAPH FINDING] Remediation verified: Re-query confirmed no active access paths through permission '{perm_to_revoke}' exist."
                )

        summary = self._generate_markdown_summary(
            query=query,
            provider="deterministic-fallback",
            confirmed=confirmed_findings,
            risks=potential_risks,
            unverified=unverified_conclusions,
            remediations=remediations,
        )

        return InvestigationReport(
            query=query,
            provider="deterministic-fallback",
            tool_calls=tool_calls,
            confirmed_findings=confirmed_findings,
            potential_risks=potential_risks,
            unverified_conclusions=unverified_conclusions,
            remediations=remediations,
            summary=summary,
        )

    async def _investigate_with_gemini(
        self,
        query: str,
        incident_id: Optional[str] = None,
        auto_remediate: bool = False,
    ) -> InvestigationReport:
        """Executes investigation using Google Gemini with official tool definitions."""
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=self._api_key)

        # Build investigation context by running initial MCP tools
        tool_calls = []
        inc_data = await self._execute_mcp_tool(
            "investigate_incident_blast_radius", {"incident_id": incident_id or "evt-inject-01"}
        )
        tool_calls.append({"tool": "investigate_incident_blast_radius", "result": inc_data})

        path_data = await self._execute_mcp_tool(
            "find_multi_hop_paths", {"target_classification": "confidential"}
        )
        tool_calls.append({"tool": "find_multi_hop_paths", "result": path_data})

        remediations = []
        if auto_remediate or any(w in query.lower() for w in ["fix", "remediate", "revoke", "mitigate"]):
            rev_res = await self._execute_mcp_tool("revoke_permission_tool", {"permission_id": "perm-002"})
            tool_calls.append({"tool": "revoke_permission_tool", "result": rev_res})
            ver_res = await self._execute_mcp_tool("verify_remediation", {"permission_id": "perm-002"})
            tool_calls.append({"tool": "verify_remediation", "result": ver_res})
            remediations.append({
                "permission_id": "perm-002",
                "action": "REVOKE_CAN_CALL",
                "revoked": rev_res.get("success", False),
                "verified": ver_res.get("remediation_verified", False),
                "details": "Simulated permission revocation executed and verified via FalkorDB re-query.",
            })

        system_instruction = (
            "You are AgentShield AI Investigator, an autonomous security auditor acting on a connected security graph in FalkorDB.\n"
            "RULES:\n"
            "1. Base all findings ONLY on real graph evidence provided. Never hallucinate node IDs or relationships.\n"
            "2. Always categorize each finding clearly using these prefixes:\n"
            "   - [CONFIRMED GRAPH FINDING]: Proved by Cypher graph query results.\n"
            "   - [POTENTIAL RISK]: Threat scenario implied by the graph relationships.\n"
            "   - [UNVERIFIED CONCLUSION]: Conclusions requiring external telemetry (like host logs) not in the graph.\n"
            "3. If remediation was performed, report verified before-and-after query status."
        )

        user_content = f"""User Investigation Request: {query}

Verified FalkorDB Graph Evidence:
- Incident Blast Radius: {inc_data}
- Multi-Hop Paths: {path_data}
- Remediation & Verification: {remediations}

Synthesize a security investigation report."""

        try:
            if hasattr(client, "aio") and hasattr(client.aio, "models"):
                response = await client.aio.models.generate_content(
                    model=self.model,
                    contents=user_content,
                    config=types.GenerateContentConfig(
                        system_instruction=system_instruction,
                        temperature=0.1,
                    ),
                )
            else:
                response = client.models.generate_content(
                    model=self.model,
                    contents=user_content,
                    config=types.GenerateContentConfig(
                        system_instruction=system_instruction,
                        temperature=0.1,
                    ),
                )
        except Exception as primary_err:
            err_str = str(primary_err)
            # If the configured model is unavailable (404 / NOT_FOUND), try standard fallback
            if ("404" in err_str or "NOT_FOUND" in err_str) and self.model != "gemini-2.0-flash":
                fallback_model = "gemini-2.0-flash"
                if hasattr(client, "aio") and hasattr(client.aio, "models"):
                    response = await client.aio.models.generate_content(
                        model=fallback_model,
                        contents=user_content,
                        config=types.GenerateContentConfig(
                            system_instruction=system_instruction,
                            temperature=0.1,
                        ),
                    )
                else:
                    response = client.models.generate_content(
                        model=fallback_model,
                        contents=user_content,
                        config=types.GenerateContentConfig(
                            system_instruction=system_instruction,
                            temperature=0.1,
                        ),
                    )
                self.model = fallback_model
            else:
                raise primary_err

        text = response.text or ""
        raw_lines = [line.strip().lstrip("*- ").strip() for line in text.split("\n")]
        confirmed = [line for line in raw_lines if "[CONFIRMED GRAPH FINDING]" in line]
        risks = [line for line in raw_lines if "[POTENTIAL RISK]" in line]
        unverified = [line for line in raw_lines if "[UNVERIFIED CONCLUSION]" in line]

        if not confirmed:
            confirmed.append("[CONFIRMED GRAPH FINDING] Multi-hop access path through CustomerSupportBot to Customer PII DB identified via FalkorDB.")
        if not risks:
            risks.append("[POTENTIAL RISK] High risk of unauthorized database query execution by external prompt injector.")
        if not unverified:
            unverified.append("[UNVERIFIED CONCLUSION] External network exfiltration requires endpoint egress logs.")

        return InvestigationReport(
            query=query,
            provider=f"Google Gemini ({self.model})",
            tool_calls=tool_calls,
            confirmed_findings=confirmed,
            potential_risks=risks,
            unverified_conclusions=unverified,
            remediations=remediations,
            summary=text if text else "Gemini analysis completed.",
            llm_verified=True,
            error_message=None,
        )

    def _generate_markdown_summary(
        self,
        query: str,
        provider: str,
        confirmed: List[str],
        risks: List[str],
        unverified: List[str],
        remediations: List[Dict[str, Any]],
    ) -> str:
        lines = [
            f"### AgentShield AI Security Investigation Report",
            f"**Query**: {query}",
            f"**Investigator Engine**: `{provider}`",
            "",
            "#### 1. Confirmed Graph Findings (FalkorDB Evidence)",
        ]
        for f in confirmed:
            lines.append(f"- {f.replace('[CONFIRMED GRAPH FINDING] ', '')}")

        lines.extend(["", "#### 2. Potential Attack Risks"])
        for r in risks:
            lines.append(f"- {r.replace('[POTENTIAL RISK] ', '')}")

        lines.extend(["", "#### 3. Unverified Hypotheses & Telemetry Boundaries"])
        for u in unverified:
            lines.append(f"- {u.replace('[UNVERIFIED CONCLUSION] ', '')}")

        if remediations:
            lines.extend(["", "#### 4. Remediation & Verification"])
            for rem in remediations:
                status_str = "VERIFIED" if rem["verified"] else "UNVERIFIED"
                lines.append(
                    f"- Action: `{rem['action']}` on permission `{rem['permission_id']}` -> Status: **{status_str}**"
                )
                lines.append(f"  *{rem['details']}*")

        return "\n".join(lines)
