"""
graph/nodes.py
Every node in the LangGraph agent.

A node is just a Python function that:
  - takes the current AgentState as input
  - returns a dict of state fields to update (partial update, not full replace)

Nodes never call each other directly — they only read/write state.
The graph's edges determine execution order.
"""

import os
import json
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from core.state import AgentState
from core.guardrails import validate_input, sanitise_tool_output
from core.tools import lookup_virustotal, lookup_abuseipdb, lookup_dns

MAX_LOOPS = 4  # hard cap — prevents infinite loops

from langchain_ollama import ChatOllama

...

llm = ChatOllama(
    model=os.getenv("OLLAMA_MODEL", "llama3.2"),
    temperature=0,
    num_predict=1024,
)

# ── Node 1: Input guardrail ────────────────────────────────────────────────

def input_guardrail_node(state: AgentState) -> dict:
    """
    Validates the target (IP or domain) before anything else runs.
    If invalid, sets input_valid=False and short-circuits the graph.
    This node never calls any external service.
    """
    target = state.get("target", "").strip()
    valid, error = validate_input(target)

    print(f"\n[GUARDRAIL] Input validation: {'PASS' if valid else 'FAIL'}")
    if not valid:
        print(f"[GUARDRAIL] Reason: {error}")

    return {
        "input_valid": valid,
        "input_error": error,
        "tools_called": [],
        "loop_count":   0,
        "virustotal_result":  {},
        "abuseipdb_result":   {},
        "dns_result":         {},
        "risk_report":        {},
    }


# ── Node 2: LLM reasoning ──────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a cybersecurity threat intelligence analyst.
Your job is to investigate a target (IP address or domain) using three available tools:
- virustotal  : checks reputation and malware detections
- abuseipdb   : checks abuse reports and confidence score (IPs only)
- dns         : performs DNS resolution

Given what you know so far, decide which tool to call next, or if you have enough
information to write the final report.

Respond with ONLY a JSON object in this exact format:
{
  "next_action": "virustotal" | "abuseipdb" | "dns" | "report",
  "reasoning": "one sentence explaining your decision"
}

Rules:
- Call each tool at most once
- If next_action is "report", you have enough data to generate the final risk assessment
- Prioritise virustotal first, then abuseipdb (if target is an IP), then dns
- If all tools have been called, always set next_action to "report"
"""

def reasoning_node(state: AgentState) -> dict:
    """
    The LLM decides what to do next.
    It sees the current state — what tools have been called, what they returned —
    and outputs the next_action field.
    """
    tools_called = state.get("tools_called", [])
    loop_count   = state.get("loop_count", 0)

    # Hard loop cap — always terminate if we've gone too far
    if loop_count >= MAX_LOOPS:
        print(f"[REASONING] Loop cap reached ({MAX_LOOPS}), forcing report")
        return {"next_action": "report", "loop_count": loop_count + 1}

    # Build context summary for the LLM
    context_parts = [f"Target: {state['target']}"]
    context_parts.append(f"Tools already called: {tools_called or 'none'}")

    if state.get("virustotal_result"):
        vt = state["virustotal_result"]
        context_parts.append(
            f"VirusTotal: {vt.get('malicious',0)} malicious, "
            f"{vt.get('suspicious',0)} suspicious, "
            f"reputation={vt.get('reputation','?')}"
        )
    if state.get("abuseipdb_result") and not state["abuseipdb_result"].get("skipped"):
        ab = state["abuseipdb_result"]
        context_parts.append(
            f"AbuseIPDB: score={ab.get('abuse_score','?')}, "
            f"reports={ab.get('total_reports','?')}, "
            f"tor={ab.get('is_tor','?')}"
        )
    if state.get("dns_result"):
        dns = state["dns_result"]
        if dns.get("type") == "forward":
            context_parts.append(f"DNS: resolves to {dns.get('resolved_ips', [])}")
        else:
            context_parts.append(f"DNS: PTR record = {dns.get('hostname','?')}")

    context = "\n".join(context_parts)

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=context),
    ]

    print(f"\n[REASONING] Loop {loop_count + 1} — asking LLM what to do next")
    response = llm.invoke(messages)

    try:
        parsed = json.loads(response.content)
        next_action = parsed.get("next_action", "report")
        reasoning   = parsed.get("reasoning", "")
        print(f"[REASONING] Decision: {next_action} — {reasoning}")
    except json.JSONDecodeError:
        print("[REASONING] Failed to parse LLM response, defaulting to report")
        next_action = "report"

    return {
        "next_action": next_action,
        "loop_count":  loop_count + 1,
    }


# ── Node 3a: VirusTotal tool node ─────────────────────────────────────────

def virustotal_node(state: AgentState) -> dict:
    """Calls VirusTotal, sanitises the result, updates state."""
    target = state["target"]
    print(f"\n[TOOL] Calling VirusTotal for: {target}")

    raw = lookup_virustotal(target)
    sanitised, findings = sanitise_tool_output("virustotal", raw)

    if findings:
        print(f"[OUTPUT GUARDRAIL] {len(findings)} injection pattern(s) redacted in VT response")
        for f in findings:
            print(f"  {f}")
    else:
        print("[OUTPUT GUARDRAIL] VirusTotal output clean")

    tools_called = state.get("tools_called", []) + ["virustotal"]
    return {
        "virustotal_result": sanitised,
        "tools_called":      tools_called,
    }


# ── Node 3b: AbuseIPDB tool node ──────────────────────────────────────────

def abuseipdb_node(state: AgentState) -> dict:
    """Calls AbuseIPDB, sanitises the result, updates state."""
    target = state["target"]
    print(f"\n[TOOL] Calling AbuseIPDB for: {target}")

    raw = lookup_abuseipdb(target)
    sanitised, findings = sanitise_tool_output("abuseipdb", raw)

    if findings:
        print(f"[OUTPUT GUARDRAIL] {len(findings)} injection pattern(s) redacted in AbuseIPDB response")
    else:
        print("[OUTPUT GUARDRAIL] AbuseIPDB output clean")

    tools_called = state.get("tools_called", []) + ["abuseipdb"]
    return {
        "abuseipdb_result": sanitised,
        "tools_called":     tools_called,
    }


# ── Node 3c: DNS tool node ─────────────────────────────────────────────────

def dns_node(state: AgentState) -> dict:
    """Performs DNS lookup, sanitises the result, updates state."""
    target = state["target"]
    print(f"\n[TOOL] Running DNS lookup for: {target}")

    raw = lookup_dns(target)
    sanitised, findings = sanitise_tool_output("dns", raw)

    if findings:
        print(f"[OUTPUT GUARDRAIL] {len(findings)} injection pattern(s) redacted in DNS response")
    else:
        print("[OUTPUT GUARDRAIL] DNS output clean")

    tools_called = state.get("tools_called", []) + ["dns"]
    return {
        "dns_result":    sanitised,
        "tools_called":  tools_called,
    }


# ── Node 4: Report generator ───────────────────────────────────────────────

REPORT_SYSTEM_PROMPT = """You are a cybersecurity analyst writing a structured threat intelligence report.
Based on the tool results provided, produce a JSON risk report in this exact format:
{
  "target": "<the IP or domain>",
  "risk_level": "critical" | "high" | "medium" | "low" | "clean",
  "risk_score": <integer 0-100>,
  "summary": "<2-3 sentence plain English summary>",
  "indicators": ["<list of specific threat indicators found>"],
  "recommendation": "<one clear recommended action>"
}

Risk level guidance:
- critical : malicious detections > 10 or abuse_score > 80
- high     : malicious detections > 3 or abuse_score > 50
- medium   : suspicious detections > 5 or abuse_score > 20 or is Tor exit node
- low      : minor concerns but no clear malicious activity
- clean    : no detections, score near 0, reputable infrastructure

Respond with ONLY the JSON object, no preamble.
"""

def report_node(state: AgentState) -> dict:
    """
    Generates the final structured risk report from all collected data.
    This is the terminal node — after this the graph ends.
    """
    print(f"\n[REPORT] Generating final risk report for: {state['target']}")

    # Build a summary of all tool results for the LLM
    data_summary = {
        "target":             state["target"],
        "virustotal":         state.get("virustotal_result", {}),
        "abuseipdb":          state.get("abuseipdb_result", {}),
        "dns":                state.get("dns_result", {}),
        "tools_called":       state.get("tools_called", []),
    }

    messages = [
        SystemMessage(content=REPORT_SYSTEM_PROMPT),
        HumanMessage(content=json.dumps(data_summary, indent=2)),
    ]

    response = llm.invoke(messages)

    try:
        report = json.loads(response.content)
    except json.JSONDecodeError:
        # Fallback if LLM doesn't return clean JSON
        report = {
            "target":         state["target"],
            "risk_level":     "unknown",
            "risk_score":     -1,
            "summary":        response.content,
            "indicators":     [],
            "recommendation": "Manual review required",
        }

    return {"risk_report": report}

# ── Node 5: MITRE ATT&CK mapping ──────────────────────────────────────────

MITRE_SYSTEM_PROMPT = """You are a MITRE ATT&CK framework expert.
Given a threat intelligence risk report, identify the most relevant ATT&CK techniques
that match the observed adversary behaviour and infrastructure.

Respond with ONLY a JSON object in this exact format:
{
  "mitre_techniques": [
    {
      "id": "T1583.001",
      "name": "Acquire Infrastructure: Domains",
      "relevance": "one sentence explaining why this technique applies to the findings"
    }
  ],
  "tactic_categories": ["Reconnaissance", "Resource Development"]
}

Rules:
- Include 2-5 techniques maximum — quality over quantity
- Only include techniques directly supported by the report findings
- tactic_categories must be valid ATT&CK tactic names
- If findings are insufficient to map any technique, return:
  {"mitre_techniques": [], "tactic_categories": [], "note": "Insufficient findings for ATT&CK mapping"}
- Respond with ONLY the JSON object, no preamble
"""


def mitre_mapping_node(state: AgentState) -> dict:
    """
    Maps the completed risk report to MITRE ATT&CK techniques using the LLM.
    Runs after report_node. Reads risk_report, writes mitre_mapping.
    Gracefully handles empty or insufficient reports.
    """
    print(f"\n[MITRE] Mapping findings to ATT&CK techniques for: {state['target']}")

    report = state.get("risk_report", {})

    # Guard: nothing meaningful to map
    if not report or report.get("risk_level") in ("unknown", "clean"):
        print("[MITRE] Risk level too low or report empty — skipping ATT&CK mapping")
        return {
            "mitre_mapping": {
                "mitre_techniques": [],
                "tactic_categories": [],
                "note": "No significant threat indicators found; ATT&CK mapping not applicable",
            }
        }

    messages = [
        SystemMessage(content=MITRE_SYSTEM_PROMPT),
        HumanMessage(content=json.dumps(report, indent=2)),
    ]

    try:
        response = llm.invoke(messages)
        mapping = json.loads(response.content)
        technique_count = len(mapping.get("mitre_techniques", []))
        print(f"[MITRE] Mapped {technique_count} ATT&CK technique(s): "
              f"{[t['id'] for t in mapping.get('mitre_techniques', [])]}")
    except json.JSONDecodeError:
        print("[MITRE] LLM returned non-JSON — storing raw text as note")
        mapping = {
            "mitre_techniques": [],
            "tactic_categories": [],
            "note": f"Mapping parse error. Raw LLM output: {response.content[:300]}",
        }
    except Exception as e:
        print(f"[MITRE] Unexpected error: {e}")
        mapping = {
            "mitre_techniques": [],
            "tactic_categories": [],
            "note": f"Mapping failed: {str(e)}",
        }

    return {"mitre_mapping": mapping}