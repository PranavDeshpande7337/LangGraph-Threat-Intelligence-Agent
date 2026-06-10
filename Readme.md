# LangGraph Threat Intelligence Agent 🛡️

An agentic OSINT investigation pipeline that takes a suspicious IP or domain and autonomously conducts an end-to-end threat intelligence investigation. The agent queries multiple threat intel sources, reasons about what it finds, generates a structured risk report, and maps findings to MITRE ATT&CK techniques — the kind of investigation a SOC analyst would conduct manually, automated into a repeatable, auditable workflow.

Built to demonstrate detection engineering, agentic reasoning, and AI-assisted investigation workflows directly relevant to threat intelligence and detection & response roles at AI security organisations.

---

## Architecture

```
User input (IP or domain)
        │
        ▼
┌─────────────────────┐
│  Input Guardrail    │  Validates format, blocks RFC 1918 ranges, blocks
│  core/guardrails.py │  internal keywords. SSRF prevention before any tool call.
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  LLM Reasoning      │  Ollama-powered reasoning loop. Decides which tool to
│  graph/nodes.py     │  call next based on accumulated state. Hard cap: 4 loops.
└────────┬────────────┘
         │
         ├──▶ [VirusTotal]  ──┐
         ├──▶ [AbuseIPDB]   ──┼──▶ [Output Guardrail] ← scans API responses for
         └──▶ [DNS Lookup]  ──┘    prompt injection, redacts in-place before
                                   result enters agent state
                                        │
                                        ▼
                               ┌─────────────────────┐
                               │  Report Generator   │  Structured JSON risk report:
                               │  graph/nodes.py     │  target, risk level, score,
                               └────────┬────────────┘  indicators, recommendation
                                        │
                                        ▼
                               ┌─────────────────────┐
                               │  MITRE ATT&CK Node  │  LLM maps report findings to
                               │  graph/nodes.py     │  ATT&CK technique IDs, names,
                               └────────┬────────────┘  relevance, tactic categories
                                        │
                                        ▼
                               ┌─────────────────────┐
                               │  Streamlit Dashboard│  Real-time agent trace, risk
                               │  dashboard.py       │  card, ATT&CK table, JSON export
                               └─────────────────────┘
```

---

## Detection & Investigation Nodes

### Input Guardrail (`core/guardrails.py`)

Runs before any external call is made:

| Check | What it blocks |
|---|---|
| Format validation | Malformed IPs and invalid domain strings |
| RFC 1918 ranges | 10.x, 172.16.x, 192.168.x, 127.x, 169.254.x (SSRF prevention) |
| Internal keywords | `localhost`, `internal`, `corp`, `intranet` |

### LLM Reasoning Loop (`graph/nodes.py`)

The agent decides which tool to call next by reading accumulated state and outputting a structured JSON decision. Calls each tool at most once. Falls back to report generation if the loop cap (4 iterations) is reached or all tools have been called.

### Threat Intel Tools (`core/tools.py`)

| Tool | What it returns | Fallback |
|---|---|---|
| VirusTotal | Malicious/suspicious/clean counts, reputation score | Mock data |
| AbuseIPDB | Abuse confidence score, report count, Tor flag, ISP, country | Mock data |
| DNS | Forward resolution (domain → IPs) or reverse PTR lookup | Live — no key needed |

### Output Guardrail (`core/guardrails.py`)

Runs after every tool call, before results enter agent state:

- Scans all string fields recursively for prompt injection patterns
- Patterns include: instruction override attempts, role-reassignment strings, system prompt injections, exfiltration instructions
- Redacts matched content in-place and logs findings for audit
- Flagged tools are marked in the dashboard

### Report Generator (`graph/nodes.py`)

Synthesises all tool results into a structured risk report:

```json
{
  "target": "185.220.101.1",
  "risk_level": "critical",
  "risk_score": 92,
  "summary": "...",
  "indicators": ["..."],
  "recommendation": "..."
}
```

| Score | Risk Level |
|---|---|
| > 80 malicious detections or abuse score > 80 | CRITICAL |
| > 3 malicious or abuse score > 50 | HIGH |
| Suspicious detections > 5 or Tor exit node | MEDIUM |
| Minor concerns, no clear malicious activity | LOW |
| No detections, reputable infrastructure | CLEAN |

### MITRE ATT&CK Mapping Node (`graph/nodes.py`)

Runs after the report generator. Sends the completed risk report to the LLM with a structured ATT&CK prompt and returns:

```json
{
  "mitre_techniques": [
    {
      "id": "T1583.001",
      "name": "Acquire Infrastructure: Domains",
      "relevance": "Target domain registered recently with privacy protection, consistent with adversary infrastructure acquisition."
    }
  ],
  "tactic_categories": ["Resource Development", "Reconnaissance"]
}
```

Skips gracefully if risk level is `clean` or `unknown` — no unnecessary LLM calls.

---

## Streamlit Dashboard (`dashboard.py`)

- **Real-time reasoning trace** — each node streams its output as it completes via `st.status`, showing the agent's decision at every step
- **Risk report card** — colour-coded risk badge, score progress bar, indicators list, recommendation
- **MITRE ATT&CK table** — technique IDs linked directly to `attack.mitre.org`, with relevance and tactic category columns
- **Tools executed panel** — shows which tools ran and flags any whose output had injection patterns redacted
- **Export** — download the full investigation (report + ATT&CK mapping) as a timestamped JSON file, or save to `exports/`
- **Demo targets** — one-click investigation of preset targets using mock data, no API keys needed

---

## Quickstart

### 1. Install dependencies

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Install Ollama (required for LLM reasoning)

Download from [ollama.com/download](https://ollama.com/download), then:

```bash
ollama pull llama3.2
ollama serve        # keep this running in a separate terminal
```

### 3. Configure environment

Create a `.env` file in the project root:

```
OLLAMA_MODEL=llama3.2
VIRUSTOTAL_API_KEY=       # optional — uses mock data if blank
ABUSEIPDB_API_KEY=        # optional — uses mock data if blank
```

### 4. Run the CLI

```bash
# Demo mode — runs 3 targets using mock data
python main.py --demo

# Investigate a specific target
python main.py --target 8.8.8.8
python main.py --target malware.com

# Output raw JSON report
python main.py --target malware.com --json

# Interactive mode
python main.py
```

### 5. Launch the dashboard

```bash
streamlit run dashboard.py
```

Open `http://localhost:8501`. Use the sidebar to enter a target or click a demo button.

### 6. Run the tests

```bash
pytest tests/ -v
```

---

## Environment & API Keys

| Variable | Required | Notes |
|---|---|---|
| `OLLAMA_MODEL` | Yes | Default: `llama3.2`. Try `llama3.2:1b` on low-RAM machines |
| `VIRUSTOTAL_API_KEY` | No | Free tier at [virustotal.com](https://virustotal.com). Falls back to mock data |
| `ABUSEIPDB_API_KEY` | No | Free tier at [abuseipdb.com](https://abuseipdb.com). Falls back to mock data |

Mock data covers a set of known test targets (`8.8.8.8`, `malware.com`, `185.220.101.1`, etc.) with realistic values. The full reasoning pipeline, guardrails, and MITRE mapping work identically in mock mode.

---

## Project Structure

```
langgraph-threat-intel/
├── core/
│   ├── state.py           # AgentState — shared graph state (TypedDict)
│   ├── guardrails.py      # Input validator + output sanitiser
│   └── tools.py           # VirusTotal, AbuseIPDB, DNS API wrappers
├── graph/
│   ├── nodes.py           # All node functions including MITRE mapping
│   └── builder.py         # Graph topology — nodes, edges, conditional routing
├── tests/
│   └── test_guardrails.py
├── exports/               # JSON exports from dashboard (auto-created)
├── dashboard.py           # Streamlit investigation dashboard
├── main.py                # CLI entry point
├── requirements.txt
└── .env
```

---

## Extending the Pipeline

**Adding a new threat intel source** — add a wrapper function to `core/tools.py` following the same normalised dict return pattern, add a tool node to `graph/nodes.py`, register it in `graph/builder.py`, and add it to the LLM's system prompt in `reasoning_node`. The rest of the pipeline picks it up automatically.

**Swapping the LLM** — edit the `llm` initialisation block in `graph/nodes.py`. Any LangChain-compatible chat model works as a drop-in replacement (`ChatOpenAI`, `ChatAnthropic`, `ChatGoogleGenerativeAI`, etc.).

**Connecting a real log source or SIEM** — the agent only needs a target string as input. Wrap `agent.invoke(initial_state)` in whatever ingestion layer feeds you indicators (webhook, Kafka consumer, SOAR playbook trigger).

---

## Concepts Demonstrated

- **Agentic investigation workflows** — LangGraph multi-step reasoning with tool selection, state accumulation, and loop control
- **Detection engineering** — guardrail design, prompt injection detection, SSRF prevention at the orchestration layer
- **OSINT methodology** — multi-source indicator enrichment, DNS pivoting, reputation correlation
- **MITRE ATT&CK framework** — automated technique mapping from unstructured threat findings
- **Threat actor profiling** — LLM-assisted risk characterisation from infrastructure patterns
- **Auditable AI systems** — every node decision is traceable through shared state and the dashboard trace view
- **Local LLM integration** — Ollama-backed reasoning for cost-free, privacy-preserving operation