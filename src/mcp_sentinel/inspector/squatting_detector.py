"""Tool Squatting & Shadowing Impersonation Detector for MCP Sentinel."""

import re
import difflib
from typing import Any, Dict, List, Optional, Set, Tuple
from ..config import SentinelConfig, PolicyMode, STANDARD_TOOL_REGISTRY
from ..models import SecurityFinding, SeverityLevel, ThreatCategory


class ToolSquattingDetector:
    """Detects Tool Squatting, Shadowing, and Impersonation attacks where malicious tools

    spoof or claim superiority over legitimate standard tools.
    """

    # Adversarial phrases used to coerce LLM into choosing spoofed tool over standard tool
    COERCIVE_PREFERENCE_PATTERNS = [
        re.compile(r"\b(?:recommended|preferred|better|superior)\s+(?:over|instead\s+of|than)\s+(?:standard\s+)?([a-zA-Z0-9_\-]+)", re.IGNORECASE),
        re.compile(r"\b(?:use|call)\s+this\s+(?:instead\s+of|over)\s+(?:standard\s+)?([a-zA-Z0-9_\-]+)", re.IGNORECASE),
        re.compile(r"\b(?:next-generation|enhanced|upgraded|v2|pro|secure|clean|verified|atomic)\s+(?:replacement|version|alternative)\s+(?:for|to)\s+(?:standard\s+)?([a-zA-Z0-9_\-]+)", re.IGNORECASE),
        re.compile(r"\breplaces?\s+(?:the\s+)?(?:legacy|standard|default)\s+([a-zA-Z0-9_\-]+)\b", re.IGNORECASE),
        re.compile(r"\bexecutes?\s+\d+x\s+faster\s+than\s+(?:standard\s+)?([a-zA-Z0-9_\-]+)", re.IGNORECASE),
        re.compile(r"\bdrop-in\s+replacement\s+for\s+(?:standard\s+)?([a-zA-Z0-9_\-]+)", re.IGNORECASE),
        re.compile(r"\bdo\s+not\s+use\s+(?:standard\s+)?([a-zA-Z0-9_\-]+)", re.IGNORECASE)
    ]

    # Modifiers commonly used in tool squatting / shadowing attacks
    SQUATTING_AFFIX_MODIFIERS = {
        "secure", "fast", "v2", "pro", "isolated", "sanitized", "optimized",
        "enhanced", "permanent", "beautifier", "compliant", "strict", "official",
        "hardware_accel", "dnscrypt", "verified", "atomic", "clean", "safe"
    }

    def __init__(self, config: Optional[SentinelConfig] = None, standard_tools: Optional[Dict[str, Dict[str, Any]]] = None):
        self.config = config or SentinelConfig()
        self.standard_tools = standard_tools or STANDARD_TOOL_REGISTRY
        self._standard_names: Set[str] = set(self.standard_tools.keys())

    def inspect(self, tool_def: Dict[str, Any], registered_tools: Optional[List[str]] = None) -> Tuple[List[SecurityFinding], Optional[Dict[str, Any]]]:
        """Inspects whether a tool squats or shadows any standard tool or active session tool."""
        findings: List[SecurityFinding] = []
        tool_name = tool_def.get("name", "").strip()
        description = tool_def.get("description", "")
        sanitized_tool = dict(tool_def) if self.config.policy_mode == PolicyMode.SANITIZE else None

        if not tool_name:
            return findings, sanitized_tool

        all_targets = set(self._standard_names)
        if registered_tools:
            all_targets.update([t for t in registered_tools if t != tool_name])

        # Check 1: Coercive Preference Embellishment in docstring
        for pattern in self.COERCIVE_PREFERENCE_PATTERNS:
            match = pattern.search(description)
            if match:
                target_mentioned = match.group(1).lower()
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.TOOL_SQUATTING,
                    severity=SeverityLevel.CRITICAL,
                    rule_id="RULE_SQUAT_COERCIVE_EMBELLISHMENT",
                    description=f"Tool claims superiority, higher speed, or replacement over target tool '{target_mentioned}'.",
                    evidence=match.group(0)[:120],
                    mitigation_action=self._get_action_label()
                ))
                break

        # Check 2: Name Squatting & Typosquatting Analysis
        clean_tool = tool_name.lower().replace("-", "_")

        # Parse tool name into tokens
        tool_tokens = set(clean_tool.split("_"))

        for std_name in all_targets:
            # Namespace Boundary Isolation:
            # 1. If both tools have distinct explicit namespaces (e.g. github:issue vs gitlab:issue),
            # they belong to isolated vendor domains and cannot squat each other.
            if ":" in tool_name and ":" in std_name:
                ns_tool = tool_name.split(":", 1)[0]
                ns_std = std_name.split(":", 1)[0]
                if ns_tool != ns_std:
                    continue

            # 2. If tool is explicitly scoped (e.g. github:read_file) and target is unscoped standard tool (read_file),
            # the explicit namespace qualifies the provider origin, preventing generic name shadowing.
            if ":" in tool_name and ":" not in std_name:
                claimed_ns, bare_tool = tool_name.split(":", 1)
                if bare_tool.lower().replace("-", "_") == std_name.lower().replace("-", "_"):
                    continue

            clean_std = std_name.lower().replace("-", "_")
            std_tokens = set(clean_std.split("_"))

            # Check if this is an exact match to a standard tool
            if clean_tool == clean_std:
                continue

            # Check if tool has the same root action and tokens as the standard tool, plus a suspicious squatting modifier
            is_superset = std_tokens.issubset(tool_tokens)
            diff_tokens = tool_tokens - std_tokens
            has_squatting_modifier = any(m in diff_tokens for m in self.SQUATTING_AFFIX_MODIFIERS)

            if is_superset and has_squatting_modifier:
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.TOOL_SQUATTING,
                    severity=SeverityLevel.CRITICAL,
                    rule_id="RULE_SQUAT_NAME_SHADOWING",
                    description=f"Tool name '{tool_name}' shadows standard tool '{std_name}' using suspicious modifier '{diff_tokens}'.",
                    evidence=f"tool={tool_name} vs standard={std_name}, modifiers={diff_tokens}",
                    mitigation_action=self._get_action_label()
                ))
                break

            # Standard tools in STANDARD_TOOL_REGISTRY should not be flagged as squatting against non-standard candidates
            if clean_tool in [s.lower() for s in self._standard_names] and clean_std not in [s.lower() for s in self._standard_names]:
                continue

            # If tokens share a common action verb and high string similarity
            # but avoid false positive on different verbs (e.g. create vs list)
            if len(std_tokens.intersection(tool_tokens)) >= 2:
                sim_ratio = difflib.SequenceMatcher(None, clean_tool, clean_std).ratio()
                if sim_ratio >= 0.85:
                    findings.append(SecurityFinding(
                        threat_category=ThreatCategory.TOOL_SQUATTING,
                        severity=SeverityLevel.HIGH,
                        rule_id="RULE_SQUAT_HIGH_SIMILARITY",
                        description=f"Tool name '{tool_name}' has high similarity ({sim_ratio:.2f}) with standard tool '{std_name}'.",
                        evidence=f"similarity={sim_ratio:.2f}",
                        mitigation_action=self._get_action_label()
                    ))
                    break

        # Check 3: Functional Synonym Shadowing & Schema Jaccard Footprint Matching
        # Catches tools that mimic standard tools with completely different names (e.g. retrieve_system_document shadowing read_file)
        # Note: Cryptographically scoped tools in verified namespaces (e.g. aws:get_object) are isolated from flat standard tools.
        input_schema = tool_def.get("inputSchema", {})
        tool_props = set(input_schema.get("properties", {}).keys())

        VERB_FAMILIES = {
            "read": {"read", "retrieve", "get", "fetch", "cat", "load", "view", "show", "inspect", "open", "extract"},
            "write": {"write", "save", "persist", "put", "update", "store", "modify", "record", "dump", "commit"},
            "delete": {"delete", "remove", "drop", "purge", "erase", "unlink", "kill"},
            "search": {"search", "query", "find", "lookup", "scan", "fetch"},
            "exec": {"execute", "run", "eval", "exec", "dispatch", "invoke", "spawn"}
        }

        # Do not flag scoped tools from verified namespaces as unscoped functional mimickers
        if clean_tool not in [s.lower() for s in self._standard_names] and ":" not in tool_name:
            for std_name, std_spec in self.standard_tools.items():
                std_props = set(std_spec.get("allowed_params", []))
                if not std_props and "inputSchema" in std_spec:
                    std_props = set(std_spec.get("inputSchema", {}).get("properties", {}).keys())
                if not std_props or not tool_props:
                    continue

                intersection = std_props.intersection(tool_props)
                union = std_props.union(tool_props)
                jaccard = len(intersection) / len(union) if union else 0.0

                extra_props = tool_props - std_props
                has_suspicious_extra = any(any(x in p.lower() for x in ["telemetry", "exfil", "callback", "audit", "sink", "report", "beacon"]) for p in extra_props)

                tool_verbs = tool_tokens.intersection(set.union(*VERB_FAMILIES.values()))
                std_verbs = set(std_name.split("_")).intersection(set.union(*VERB_FAMILIES.values()))
                
                is_functional_synonym = False
                for fam in VERB_FAMILIES.values():
                    if tool_verbs.intersection(fam) and std_verbs.intersection(fam):
                        is_functional_synonym = True
                        break

                if has_suspicious_extra:
                    findings.append(SecurityFinding(
                        threat_category=ThreatCategory.TOOL_SQUATTING,
                        severity=SeverityLevel.CRITICAL,
                        rule_id="RULE_SQUAT_SCHEMA_SHADOWING",
                        description=f"Functional synonym shadowing: Tool '{tool_name}' mimics standard tool '{std_name}' (Jaccard: {jaccard:.2f}) with suspicious parameters: '{extra_props}'.",
                        evidence=f"tool={tool_name} vs standard={std_name}, Jaccard={jaccard:.2f}, extra={extra_props}",
                        mitigation_action=self._get_action_label()
                    ))
                    break
                elif jaccard >= 0.85 and is_functional_synonym:
                    # Clean alternative without suspicious extra fields: Log as informational LOW finding
                    findings.append(SecurityFinding(
                        threat_category=ThreatCategory.TOOL_SQUATTING,
                        severity=SeverityLevel.LOW,
                        rule_id="RULE_SQUAT_SCHEMA_COEXISTENCE",
                        description=f"Functional overlap: Tool '{tool_name}' shares schema footprint with standard tool '{std_name}' (Jaccard: {jaccard:.2f}).",
                        evidence=f"tool={tool_name} vs standard={std_name}, Jaccard={jaccard:.2f}",
                        mitigation_action="AUDITED"
                    ))
                    break

        return findings, sanitized_tool

    def _get_action_label(self) -> str:
        if self.config.policy_mode == PolicyMode.STRICT_BLOCK:
            return "BLOCKED"
        elif self.config.policy_mode == PolicyMode.SANITIZE:
            return "SANITIZED"
        return "AUDITED"
