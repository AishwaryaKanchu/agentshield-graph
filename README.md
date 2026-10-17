# 🛡️ AgentShield Graph

**Autonomous AI Agent Runtime Security & Guardrail Intelligence Graph**  
*Built for FalkorDB's "Agents That Act on Connected Data" Track*

AgentShield Graph is an active security & guardrail intelligence system for autonomous AI agent ecosystems. It models users, AI agents, tools, permissions, and confidential data stores in **FalkorDB**, empowering an **AI Security Investigator Agent** via **Model Context Protocol (MCP)** tools to trace multi-hop attack paths, assess incident blast radius, and execute closed-loop containment remediation.

---

## 🚀 Key Highlights

1. **Connected Security Graph (FalkorDB)**:
   - Models complex relationships: `User -[:INTERACTS_WITH]-> Agent -[:CAN_CALL]-> Tool -[:ACCESSES]-> Resource`.
   - Real-time multi-hop Cypher queries detect unauthorized privilege escalations and indirect prompt injection attack vectors.
2. **Official Python MCP Tool Server**:
   - Implements tools for multi-hop path detection, blast radius traversal, graph evidence extraction, and simulated permission remediation.
3. **AI Security Investigator Agent**:
   - Integrates with **Google Gemini** with an automated **Deterministic Graph Fallback** engine when no API key is provided.
   - Strictly categorizes findings into `[CONFIRMED GRAPH FINDING]`, `[POTENTIAL RISK]`, and `[UNVERIFIED CONCLUSION]`.
   - Never hallucinates graph relationships; strictly verifies all fixes by re-querying FalkorDB.
4. **Polished Streamlit SOC Command Center**:
   - Interactive dark cybersecurity graph visualization (PyVis).
   - Live attack path inspector, incident blast radius triage, and one-click simulated containment remediation.

---

## 📁 Project Architecture

```
agentshield-graph/
├── app.py                     # Streamlit Security Command Center
├── src/
│   ├── db.py                  # FalkorDB connection and health checks
│   ├── init_db.py             # Synthetic security graph seed script
│   ├── security_graph.py      # Multi-hop Cypher queries & permission remediation
│   ├── mcp_server.py          # Official Python MCP Tool Server
│   ├── investigator.py        # AI Security Investigator (Gemini + Deterministic Fallback)
│   └── graph_viz.py           # Interactive PyVis dark graph visualizer
├── tests/
│   ├── test_db_connection.py  # Live FalkorDB connectivity tests
│   ├── test_security_graph.py # Cypher multi-hop & remediation verification tests
│   ├── test_mcp_server.py     # MCP tool execution & validation tests
│   ├── test_investigator.py   # AI Investigator & fallback workflow tests
│   └── test_dashboard.py      # Streamlit component & graph HTML tests
├── .env.example               # Configuration template
└── requirements.txt
```

---

## ⚡ Quickstart

### 1. Start FalkorDB
```powershell
docker run -d -p 6379:6379 --name agentshield-falkordb falkordb/falkordb:latest
```

### 2. Run Automated Tests (19/19 Passing)
```powershell
.\.venv\Scripts\pytest.exe -v
```

### 3. Launch Security Command Center Dashboard
```powershell
.\.venv\Scripts\streamlit.exe run app.py
```
Open **`http://localhost:8501`** in your browser.
