# LangGraph Threat Intelligence Agent

A stateful, graph-based AI security agent that investigates IPs and domains using multiple threat intel sources, with integrated security guardrail nodes at both the input and output layers.

---

## Architecture

```
User input
    │
    ▼
[Input guardrail]  ← validates IP/domain, blocks private ranges
    │
    ▼
[LLM reasoning]  ← decides which tool to call next
    │
    ├──▶ [VirusTotal]  ──┐
    ├──▶ [AbuseIPDB]   ──┼──▶ [Output guardrail]  ← sanitises API responses
    └──▶ [DNS lookup]  ──┘         │
                                   ▼
                              [LLM reasoning] (loop)
                                   │
                              [Report generator]
```

---

## Quickstart

```bash
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Copy and fill in your API keys
cp .env.example .env

# Run tests (no API keys needed)
python tests/test_guardrails.py

# Run demo (uses mock data if no API keys)
python main.py --demo

# Investigate a specific target
python main.py --target 8.8.8.8
python main.py --target malware.com

# Interactive mode
python main.py
```

---

## API Keys

| Key | Where to get it | Required? |
|-----|----------------|-----------|
| `ANTHROPIC_API_KEY` | console.anthropic.com | Yes — drives the LLM |
| `VIRUSTOTAL_API_KEY` | virustotal.com/gui/join-us | No — falls back to mock data |
| `ABUSEIPDB_API_KEY` | abuseipdb.com/register | No — falls back to mock data |

Without VirusTotal and AbuseIPDB keys the agent runs in mock mode — realistic data is returned for a set of known test targets. The LLM reasoning and guardrails work identically.

---

## Security features

**Input guardrail node** — runs before any tool is called:
- Validates IP/domain format
- Blocks RFC 1918 private IP ranges (SSRF prevention)
- Blocks internal keyword patterns (localhost, internal, corp)

**Output guardrail node** — runs after every tool call, before results enter state:
- Scans all string fields in API responses for prompt injection patterns
- Redacts matched content in-place
- Logs findings for audit

**Loop cap** — hard maximum of 4 reasoning iterations prevents runaway agents.

---

## Project structure

```
langgraph-threat-intel/
├── core/
│   ├── state.py          # AgentState — shared graph state
│   ├── guardrails.py     # input validator + output sanitiser
│   └── tools.py          # VirusTotal, AbuseIPDB, DNS wrappers
├── graph/
│   ├── nodes.py          # every node function
│   └── builder.py        # graph topology — nodes, edges, routing
├── tests/
│   └── test_guardrails.py
├── main.py
├── requirements.txt
└── .env.example
```