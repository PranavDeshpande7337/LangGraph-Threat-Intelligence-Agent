"""
graph/builder.py
Assembles all nodes and edges into a compiled LangGraph agent.

This is where the graph topology is defined:
  - which nodes exist
  - which edges connect them
  - which edges are conditional (LLM-driven routing)
"""

from langgraph.graph import StateGraph, END

from core.state import AgentState
from graph.nodes import (
    input_guardrail_node,
    reasoning_node,
    virustotal_node,
    abuseipdb_node,
    dns_node,
    report_node,
    mitre_mapping_node,          # ADDITION
)


def route_after_input_guardrail(state: AgentState) -> str:
    """
    Conditional edge after input validation.
    If invalid — go straight to END (no tools called, no LLM cost).
    If valid   — proceed to LLM reasoning.
    """
    if not state.get("input_valid", False):
        return "end"
    return "reasoning"


def route_after_reasoning(state: AgentState) -> str:
    """
    Conditional edge after LLM decides what to do next.
    Maps the LLM's next_action string to the appropriate node.
    """
    action = state.get("next_action", "report")
    tools_called = state.get("tools_called", [])

    # Guard against calling the same tool twice
    if action in tools_called:
        return "report"

    route_map = {
        "virustotal": "virustotal",
        "abuseipdb":  "abuseipdb",
        "dns":        "dns",
        "report":     "report",
    }
    return route_map.get(action, "report")


def build_graph():
    """
    Construct and compile the threat intelligence agent graph.
    Returns a compiled graph ready to invoke.
    """
    graph = StateGraph(AgentState)

    # ── Register all nodes ─────────────────────────────────────────────────
    graph.add_node("input_guardrail", input_guardrail_node)
    graph.add_node("reasoning",       reasoning_node)
    graph.add_node("virustotal",      virustotal_node)
    graph.add_node("abuseipdb",       abuseipdb_node)
    graph.add_node("dns",             dns_node)
    graph.add_node("report",          report_node)
    graph.add_node("mitre_mapping",   mitre_mapping_node)   # ADDITION

    # ── Entry point ────────────────────────────────────────────────────────
    graph.set_entry_point("input_guardrail")

    # ── Conditional edge: after input guardrail ────────────────────────────
    graph.add_conditional_edges(
        "input_guardrail",
        route_after_input_guardrail,
        {
            "reasoning": "reasoning",
            "end":       END,
        }
    )

    # ── Conditional edge: after LLM reasoning ─────────────────────────────
    graph.add_conditional_edges(
        "reasoning",
        route_after_reasoning,
        {
            "virustotal": "virustotal",
            "abuseipdb":  "abuseipdb",
            "dns":        "dns",
            "report":     "report",
        }
    )

    # ── After each tool — always go back to reasoning (the loop) ──────────
    graph.add_edge("virustotal", "reasoning")
    graph.add_edge("abuseipdb",  "reasoning")
    graph.add_edge("dns",        "reasoning")

    # ── Report → MITRE mapping → END  (ADDITION: replaced direct report→END) ──
    graph.add_edge("report",         "mitre_mapping")
    graph.add_edge("mitre_mapping",  END)

    return graph.compile()