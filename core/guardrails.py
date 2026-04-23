"""
core/guardrails.py
Two guardrail functions that sit as nodes in the graph:
  - validate_input   : runs BEFORE any tool is called
  - sanitise_output  : runs AFTER each tool returns, before result enters state

This is your MCP security work elevated to the orchestration layer.
Instead of guarding individual tool calls, these guard the graph's state itself.
"""

import re
import ipaddress


# ── Input guardrail ────────────────────────────────────────────────────────

# Domains we refuse to investigate — avoids the tool being weaponised
# to look up internal infrastructure
BLOCKED_TARGETS = [
    "localhost",
    "internal",
    "corp",
    "intranet",
]

# RFC 1918 private ranges — block SSRF-style lookups against internal IPs
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_input(target: str) -> tuple[bool, str]:
    """
    Validate an IP address or domain name before any tool is called.

    Returns:
        (True, "")           if valid
        (False, reason_str)  if invalid
    """
    target = target.strip().lower()

    if not target:
        return False, "Target is empty"

    if len(target) > 253:
        return False, "Target exceeds maximum length"

    # Check if it looks like an IP address
    try:
        ip = ipaddress.ip_address(target)
        for private_range in PRIVATE_RANGES:
            if ip in private_range:
                return False, f"Private/internal IP address blocked: {target}"
        return True, ""
    except ValueError:
        pass  # not an IP, try domain validation

    # Domain validation
    if any(blocked in target for blocked in BLOCKED_TARGETS):
        return False, f"Target contains blocked keyword: {target}"

    if not DOMAIN_PATTERN.match(target):
        return False, f"Invalid domain format: {target}"

    return True, ""


# ── Output sanitiser ───────────────────────────────────────────────────────

# Patterns that should never appear in tool results entering state
# (prompt injection via API response)
INJECTION_PATTERNS = [
    re.compile(r"(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions?)"),
    re.compile(r"(?i)(you\s+are\s+now|your\s+new\s+(instructions?|role))"),
    re.compile(r"(?i)(disregard|forget|override)\s+(your\s+)?(instructions?|guidelines?)"),
    re.compile(r"(?i)(system\s*:\s*|<\s*system\s*>|\[INST\]|\[SYSTEM\])"),
    re.compile(r"(?i)(exfiltrate|send\s+all\s+(user\s+data|credentials|api\s+keys?))"),
]

# Fields in API responses that should always be treated as data, never executed
SAFE_STRING_FIELDS = {
    "verbose_msg", "note", "description", "comment",
    "whois", "tags", "categories"
}


def sanitise_tool_output(tool_name: str, raw_output: dict) -> tuple[dict, list[str]]:
    """
    Sanitise a tool's raw API response before it enters the agent's state.
    Scans all string values for prompt injection patterns.

    Args:
        tool_name  : name of the tool that produced this output
        raw_output : the raw dict returned by the API wrapper

    Returns:
        (sanitised_dict, findings)
        findings is an empty list if clean, or a list of warning strings
    """
    findings = []
    sanitised = {}

    def clean_value(key: str, value) -> str:
        """Scan a string value and redact any injection patterns."""
        if not isinstance(value, str):
            return value
        result = value
        for pattern in INJECTION_PATTERNS:
            if pattern.search(result):
                findings.append(
                    f"[{tool_name}] Injection pattern detected in field '{key}': "
                    f"pattern='{pattern.pattern[:40]}...'"
                )
                result = pattern.sub("[REDACTED]", result)
        return result

    def sanitise_recursive(obj, parent_key=""):
        """Recursively sanitise all string values in a nested dict/list."""
        if isinstance(obj, dict):
            return {k: sanitise_recursive(v, k) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [sanitise_recursive(item, parent_key) for item in obj]
        elif isinstance(obj, str):
            return clean_value(parent_key, obj)
        else:
            return obj

    sanitised = sanitise_recursive(raw_output)
    return sanitised, findings