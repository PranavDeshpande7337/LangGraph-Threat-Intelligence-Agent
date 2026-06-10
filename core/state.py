"""
core/state.py
Defines AgentState — the single shared object that every node reads and writes.
This is the backbone of a LangGraph agent. All nodes communicate through state,
never directly with each other.
"""

from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    # ── Input ─────────────────────────────────────────────────────────────
    target: str                      # the IP or domain being investigated

    # ── Conversation / reasoning trace ────────────────────────────────────
    # add_messages is a LangGraph reducer — it appends rather than overwrites
    messages: Annotated[list, add_messages]

    # ── Tool results (populated as tools are called) ───────────────────────
    virustotal_result: dict          # raw VT response after sanitisation
    abuseipdb_result: dict           # raw AbuseIPDB response after sanitisation
    dns_result: dict                 # DNS resolution result

    # ── Guardrail flags ───────────────────────────────────────────────────
    input_valid: bool                # set by input guardrail node
    input_error: str                 # reason if input is invalid

    # ── Control flow ──────────────────────────────────────────────────────
    tools_called: list[str]          # tracks which tools have been called
    loop_count: int                  # prevents infinite loops
    next_action: str                 # LLM decision: tool name or "report"

    # ── Final output ──────────────────────────────────────────────────────
    risk_report: dict                # structured final risk report

    # ── MITRE ATT&CK mapping (populated after report_node) ────────────────
    mitre_mapping: dict              # ATT&CK techniques mapped from risk_report