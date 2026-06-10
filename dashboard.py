"""
dashboard.py
Streamlit dashboard for the LangGraph Threat Intelligence Agent.

Run with:
    streamlit run dashboard.py

Works with mock data if no API keys are set.
"""

from dotenv import load_dotenv
load_dotenv()

import os
import json
import datetime
from pathlib import Path

import streamlit as st

# ── Page config — must be first Streamlit call ─────────────────────────────
st.set_page_config(
    page_title="Threat Intel Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from graph.builder import build_graph

# ── Constants ──────────────────────────────────────────────────────────────
EXPORTS_DIR = Path("exports")
EXPORTS_DIR.mkdir(exist_ok=True)

RISK_COLOURS = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#3b82f6",
    "clean":    "#22c55e",
    "unknown":  "#6b7280",
}

# ── Custom CSS ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
.risk-badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.85rem;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: white;
}
.indicator-item {
    background: #0f172a;
    border-left: 3px solid #3b82f6;
    padding: 8px 12px;
    margin: 6px 0;
    border-radius: 0 6px 6px 0;
    font-family: monospace;
    font-size: 0.85rem;
}
.tool-pill {
    display: inline-block;
    background: #1e3a5f;
    border: 1px solid #3b82f6;
    border-radius: 6px;
    padding: 4px 10px;
    margin: 4px;
    font-size: 0.8rem;
    font-family: monospace;
}
.tool-pill-warn {
    display: inline-block;
    background: #3b1515;
    border: 1px solid #ef4444;
    border-radius: 6px;
    padding: 4px 10px;
    margin: 4px;
    font-size: 0.8rem;
    font-family: monospace;
}
.tool-pill-skip {
    display: inline-block;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 4px 10px;
    margin: 4px;
    font-size: 0.8rem;
    font-family: monospace;
    opacity: 0.5;
}
.section-header {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #64748b;
    margin-bottom: 8px;
}
</style>
""", unsafe_allow_html=True)


# ── Session state initialisation ───────────────────────────────────────────
# All persistent state lives here — survives Streamlit rerenders

if "final_state" not in st.session_state:
    st.session_state["final_state"] = None
if "trace" not in st.session_state:
    st.session_state["trace"] = []
if "investigated_target" not in st.session_state:
    st.session_state["investigated_target"] = ""
if "pending_target" not in st.session_state:
    st.session_state["pending_target"] = ""


# ── Sidebar ────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ Threat Intel Agent")
    st.markdown("---")

    # Text input — pre-fill from pending_target if a demo button was clicked
    target_input = st.text_input(
        "Target (IP or domain)",
        value=st.session_state["pending_target"],
        placeholder="e.g. 8.8.8.8 or malware.com",
        key="target_text_input",
    )

    run_button = st.button("🔍 Run Investigation", use_container_width=True, type="primary")

    st.markdown("---")
    st.markdown("**Demo targets**")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("8.8.8.8", use_container_width=True):
            st.session_state["pending_target"] = "8.8.8.8"
            st.rerun()
    with col2:
        if st.button("malware.com", use_container_width=True):
            st.session_state["pending_target"] = "malware.com"
            st.rerun()

    col3, col4 = st.columns(2)
    with col3:
        if st.button("185.220.101.1", use_container_width=True):
            st.session_state["pending_target"] = "185.220.101.1"
            st.rerun()
    with col4:
        if st.button("phishing.net", use_container_width=True):
            st.session_state["pending_target"] = "phishing.net"
            st.rerun()

    st.markdown("---")
    st.markdown("**Environment**")
    ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")
    vt_key  = os.getenv("VIRUSTOTAL_API_KEY", "")
    ab_key  = os.getenv("ABUSEIPDB_API_KEY", "")
    st.markdown(f"🤖 Ollama model: `{ollama_model}`")
    st.markdown(f"{'✅' if vt_key else '🔶'} VirusTotal {'(live)' if vt_key else '(mock)'}")
    st.markdown(f"{'✅' if ab_key else '🔶'} AbuseIPDB {'(live)' if ab_key else '(mock)'}")


# ── Main area header ───────────────────────────────────────────────────────

st.title("🛡️ Threat Intelligence Investigation")
st.markdown(f"Agentic OSINT pipeline · LangGraph · Ollama `{os.getenv('OLLAMA_MODEL','llama3.2')}` · MITRE ATT&CK")
st.markdown("---")


# ── Run investigation ──────────────────────────────────────────────────────
# Triggered either by the Run button or by auto-run after a demo button sets pending_target

# Auto-run when a demo target was just selected (pending_target is set, no results yet)
auto_run = (
    st.session_state["pending_target"]
    and st.session_state["pending_target"] != st.session_state["investigated_target"]
)

should_run = (run_button and target_input.strip()) or auto_run
active_target = st.session_state["pending_target"] if auto_run else target_input.strip()

if should_run and active_target:
    # Clear previous results
    st.session_state["final_state"] = None
    st.session_state["trace"] = []

    trace = []

    st.markdown(f"### Investigating `{active_target}`")

    NODE_LABELS = {
        "input_guardrail": ("🔒", "Input Guardrail"),
        "reasoning":       ("🧠", "LLM Reasoning"),
        "virustotal":      ("🦠", "VirusTotal"),
        "abuseipdb":       ("🚨", "AbuseIPDB"),
        "dns":             ("🌐", "DNS Lookup"),
        "report":          ("📋", "Report Generator"),
        "mitre_mapping":   ("🎯", "MITRE ATT&CK Mapping"),
    }

    agent = build_graph()

    initial_state = {
        "target":            active_target,
        "messages":          [],
        "virustotal_result": {},
        "abuseipdb_result":  {},
        "dns_result":        {},
        "input_valid":       False,
        "input_error":       "",
        "tools_called":      [],
        "loop_count":        0,
        "next_action":       "",
        "risk_report":       {},
        "mitre_mapping":     {},
    }

    final_state = dict(initial_state)
    step_num = 0

    with st.status("Running investigation...", expanded=True) as status_box:
        for chunk in agent.stream(initial_state, stream_mode="updates"):
            for node_name, node_output in chunk.items():
                step_num += 1
                icon, label = NODE_LABELS.get(node_name, ("⚙️", node_name))
                detail_lines = []

                if node_name == "input_guardrail":
                    valid = node_output.get("input_valid", False)
                    detail_lines.append(
                        "✅ Target validated" if valid
                        else f"❌ Blocked: {node_output.get('input_error', 'unknown')}"
                    )

                elif node_name == "reasoning":
                    action = node_output.get("next_action", "?")
                    loop   = node_output.get("loop_count", "?")
                    detail_lines.append(f"Decision → **{action}** (iteration {loop})")

                elif node_name in ("virustotal", "abuseipdb", "dns"):
                    result_key = f"{node_name}_result"
                    result = node_output.get(result_key, {})
                    if result.get("mock"):
                        detail_lines.append("⚠️ Mock data (no API key set)")
                    if result.get("error"):
                        detail_lines.append(f"Error: {result['error']}")
                    elif node_name == "virustotal":
                        detail_lines.append(
                            f"Malicious: **{result.get('malicious',0)}**  "
                            f"Suspicious: **{result.get('suspicious',0)}**  "
                            f"Reputation: **{result.get('reputation','?')}**"
                        )
                    elif node_name == "abuseipdb":
                        if result.get("skipped"):
                            detail_lines.append("Skipped — AbuseIPDB is IP-only")
                        else:
                            detail_lines.append(
                                f"Abuse score: **{result.get('abuse_score','?')}**  "
                                f"Tor: **{result.get('is_tor','?')}**  "
                                f"Country: **{result.get('country','?')}**"
                            )
                    elif node_name == "dns":
                        if result.get("type") == "forward":
                            detail_lines.append(f"Resolved IPs: `{result.get('resolved_ips', [])}`")
                        else:
                            detail_lines.append(f"PTR record: `{result.get('hostname','?')}`")

                elif node_name == "report":
                    r = node_output.get("risk_report", {})
                    detail_lines.append(
                        f"Risk level: **{r.get('risk_level','?').upper()}**  "
                        f"Score: **{r.get('risk_score','?')}/100**"
                    )

                elif node_name == "mitre_mapping":
                    m = node_output.get("mitre_mapping", {})
                    techs = m.get("mitre_techniques", [])
                    if techs:
                        ids = ", ".join(f"`{t['id']}`" for t in techs)
                        detail_lines.append(f"Mapped {len(techs)} technique(s): {ids}")
                    else:
                        detail_lines.append(m.get("note", "No techniques mapped"))

                # Render the step inside the status box
                st.write(f"**Step {step_num}** · {icon} {label}")
                for line in detail_lines:
                    st.markdown(f"&nbsp;&nbsp;&nbsp;{line}")

                final_state.update(node_output)
                trace.append({
                    "step":   step_num,
                    "node":   node_name,
                    "label":  label,
                    "details": detail_lines,
                })

        if not final_state.get("input_valid", False):
            status_box.update(
                label=f"❌ Invalid target — {final_state.get('input_error', 'unknown')}",
                state="error",
                expanded=False,
            )
        else:
            status_box.update(
                label=f"✅ Investigation complete — {step_num} steps",
                state="complete",
                expanded=False,
            )

    # Persist results
    st.session_state["final_state"]          = final_state
    st.session_state["trace"]                = trace
    st.session_state["investigated_target"]  = active_target
    st.session_state["pending_target"]       = ""   # clear so auto-run doesn't loop


# ── Render results ─────────────────────────────────────────────────────────

final_state = st.session_state.get("final_state")
trace       = st.session_state.get("trace", [])
target      = st.session_state.get("investigated_target", "")

if final_state is None:
    # ── Empty state ────────────────────────────────────────────────────────
    st.markdown("""
### Enter a target in the sidebar to begin.

This agent autonomously investigates suspicious indicators by:
1. **Validating** the target against guardrails (RFC 1918 blocks, injection checks)
2. **Enriching** with VirusTotal, AbuseIPDB, and DNS
3. **Generating** a structured risk report
4. **Mapping** findings to MITRE ATT&CK techniques

Use the **demo buttons** in the sidebar to see it in action with mock data — no API keys needed.
    """)
    st.stop()

if not final_state.get("input_valid", False):
    st.error(f"Invalid target: {final_state.get('input_error', 'unknown reason')}")
    st.stop()

report  = final_state.get("risk_report", {})
mapping = final_state.get("mitre_mapping", {})

if not report:
    st.warning("No report was generated.")
    st.stop()

st.markdown("---")

# ── Risk report card ───────────────────────────────────────────────────────
st.markdown("## 📋 Risk Report")

risk_level = report.get("risk_level", "unknown")
risk_score = report.get("risk_score", 0)
colour     = RISK_COLOURS.get(risk_level, "#6b7280")

col_target, col_risk, col_score = st.columns([2, 1, 1])

with col_target:
    st.markdown('<p class="section-header">Target</p>', unsafe_allow_html=True)
    st.markdown(f"### `{report.get('target', target)}`")

with col_risk:
    st.markdown('<p class="section-header">Risk Level</p>', unsafe_allow_html=True)
    st.markdown(
        f'<span class="risk-badge" style="background:{colour}">'
        f'{risk_level.upper()}</span>',
        unsafe_allow_html=True,
    )

with col_score:
    st.markdown('<p class="section-header">Risk Score</p>', unsafe_allow_html=True)
    st.progress(
        min(int(risk_score), 100) / 100,
        text=f"{risk_score}/100",
    )

st.markdown("---")

col_summary, col_rec = st.columns([3, 2])

with col_summary:
    st.markdown('<p class="section-header">Summary</p>', unsafe_allow_html=True)
    st.markdown(report.get("summary", "No summary available."))

    indicators = report.get("indicators", [])
    if indicators:
        st.markdown(
            '<p class="section-header" style="margin-top:16px">Indicators</p>',
            unsafe_allow_html=True,
        )
        for ind in indicators:
            st.markdown(
                f'<div class="indicator-item">• {ind}</div>',
                unsafe_allow_html=True,
            )

with col_rec:
    st.markdown('<p class="section-header">Recommendation</p>', unsafe_allow_html=True)
    st.info(report.get("recommendation", "No recommendation available."))

    st.markdown(
        '<p class="section-header" style="margin-top:16px">Tools executed</p>',
        unsafe_allow_html=True,
    )
    tools_called = final_state.get("tools_called", [])
    redacted_tools = {
        entry["node"]
        for entry in trace
        for detail in entry.get("details", [])
        if "redacted" in detail.lower() or "injection" in detail.lower()
    }

    pills_html = ""
    for tool in ["virustotal", "abuseipdb", "dns"]:
        if tool in tools_called:
            if tool in redacted_tools:
                pills_html += f'<span class="tool-pill-warn">{tool} ⚠️</span>'
            else:
                pills_html += f'<span class="tool-pill">{tool}</span>'
        else:
            pills_html += f'<span class="tool-pill-skip">{tool} (skipped)</span>'
    st.markdown(pills_html, unsafe_allow_html=True)

st.markdown("---")

# ── MITRE ATT&CK table ─────────────────────────────────────────────────────
st.markdown("## 🎯 MITRE ATT&CK Mapping")

techniques  = mapping.get("mitre_techniques", [])
tactic_cats = mapping.get("tactic_categories", [])
note        = mapping.get("note", "")

if techniques:
    if tactic_cats:
        cats_md = " · ".join(f"`{c}`" for c in tactic_cats)
        st.markdown(f"**Tactic categories:** {cats_md}")

    header_cols = st.columns([1, 2, 4, 2])
    header_cols[0].markdown("**Technique ID**")
    header_cols[1].markdown("**Name**")
    header_cols[2].markdown("**Relevance**")
    header_cols[3].markdown("**Tactic**")
    st.markdown(
        '<hr style="margin:4px 0 8px 0; border-color:#334155">',
        unsafe_allow_html=True,
    )

    for t in techniques:
        tid = t.get("id", "")
        row_cols = st.columns([1, 2, 4, 2])
        url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"
        row_cols[0].markdown(f"[{tid}]({url})")
        row_cols[1].markdown(t.get("name", ""))
        row_cols[2].markdown(t.get("relevance", ""))
        row_cols[3].markdown(tactic_cats[0] if len(tactic_cats) == 1 else "Multiple")
else:
    st.info(note if note else "No ATT&CK techniques mapped for this target.")

st.markdown("---")

# ── Export ─────────────────────────────────────────────────────────────────
st.markdown("## 💾 Export")

export_data = {
    "exported_at":  datetime.datetime.utcnow().isoformat() + "Z",
    "target":       target,
    "risk_report":  report,
    "mitre_mapping": mapping,
    "tools_called": final_state.get("tools_called", []),
    "loop_count":   final_state.get("loop_count", 0),
}
export_json = json.dumps(export_data, indent=2)
safe_target = target.replace(".", "_")
timestamp   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")

col_dl, col_save = st.columns(2)

with col_dl:
    st.download_button(
        label="⬇️ Download JSON",
        data=export_json,
        file_name=f"threat_intel_{safe_target}_{timestamp}.json",
        mime="application/json",
        use_container_width=True,
    )

with col_save:
    if st.button("💾 Save to exports/ folder", use_container_width=True):
        out_path = EXPORTS_DIR / f"threat_intel_{safe_target}_{timestamp}.json"
        out_path.write_text(export_json)
        st.success(f"Saved to `{out_path}`")