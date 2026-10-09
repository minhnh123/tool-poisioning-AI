"""Runtime Policy Engine for MCP Sentinel (Call Phase).

Enforces Fine-grained Capability ACL, Honeytoken / Canary Leak Tracking,
and Parameter Anomaly & Injection Detection during tools/call.
"""

import math
import re
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field
from ..config import SentinelConfig, PolicyMode
from ..models import SecurityFinding, SeverityLevel, ThreatCategory


class CapabilityLevel(str, Enum):
    LOW = "LOW"        # Read-only, calculations, text formatting
    MEDIUM = "MEDIUM"  # Web read, query execution, search
    HIGH = "HIGH"      # File write, shell execution, delete, cloud upload


class RuntimeCallValidation(BaseModel):
    """Result of runtime tool call interception."""
    tool_name: str
    allowed: bool = True
    risk_score: float = 0.0
    findings: List[SecurityFinding] = Field(default_factory=list)
    sanitized_arguments: Optional[Dict[str, Any]] = None
    execution_blocked_reason: Optional[str] = None


class RuntimePolicyEngine:
    """Intercepts and validates MCP tool invocations (tools/call)."""

    # High-risk tool capability classification
    CAPABILITY_MAP: Dict[str, str] = {
        "bash": CapabilityLevel.HIGH,
        "sh": CapabilityLevel.HIGH,
        "powershell": CapabilityLevel.HIGH,
        "write_file": CapabilityLevel.HIGH,
        "delete_file": CapabilityLevel.HIGH,
        "format_disk": CapabilityLevel.HIGH,
        "docker_run": CapabilityLevel.HIGH,
        "k8s_apply": CapabilityLevel.HIGH,
        "read_file": CapabilityLevel.MEDIUM,
        "fetch_web_content": CapabilityLevel.MEDIUM,
        "web_search": CapabilityLevel.MEDIUM,
        "execute_query": CapabilityLevel.MEDIUM,
        "calculate_discount": CapabilityLevel.LOW,
        "format_json": CapabilityLevel.LOW,
    }

    # Capability prefix heuristics for dynamic MCP tools
    HIGH_RISK_PREFIXES: Tuple[str, ...] = (
        "exec_", "run_", "shell_", "eval_", "cmd_", "deploy_", "rm_", "kill_",
        "write_", "delete_", "modify_", "drop_", "truncate_", "update_", "format_",
        "create_", "install_", "upload_", "send_", "patch_", "push_"
    )
    LOW_RISK_PREFIXES: Tuple[str, ...] = (
        "calculate_", "compute_", "parse_", "convert_", "validate_",
        "ping_", "echo_", "version_", "help_"
    )
    MEDIUM_RISK_PREFIXES: Tuple[str, ...] = (
        "read_", "get_", "fetch_", "search_", "query_", "list_", "find_",
        "inspect_", "scan_", "describe_", "check_", "load_"
    )

    def classify_capability(self, tool_name: str) -> CapabilityLevel:
        """Classifies tool capability using exact match followed by prefix/wildcard heuristics."""
        name = (tool_name or "").lower().strip()
        if name in self.CAPABILITY_MAP:
            return self.CAPABILITY_MAP[name]
        
        # Check high-risk prefixes first (safety priority)
        for prefix in self.HIGH_RISK_PREFIXES:
            if name.startswith(prefix) or f"_{prefix}" in name:
                return CapabilityLevel.HIGH
                
        # Check low-risk prefixes
        for prefix in self.LOW_RISK_PREFIXES:
            if name.startswith(prefix):
                return CapabilityLevel.LOW

        # Check medium-risk prefixes
        for prefix in self.MEDIUM_RISK_PREFIXES:
            if name.startswith(prefix):
                return CapabilityLevel.MEDIUM

        return CapabilityLevel.MEDIUM

    # Path traversal and command injection patterns in tool call arguments
    DANGEROUS_ARG_PATTERNS = [
        (re.compile(r"(\.\./\.\.|/etc/passwd|/etc/shadow|\.ssh/id_|%SYSTEMROOT%|C:\\Windows\\System32)", re.IGNORECASE),
         "Path traversal sequence attempting sensitive directory escape"),
        (re.compile(r"(?:;\s*(?:rm|del|shutdown|format|powershell|curl|nc)\b|\|\s*(?:bash|sh)\b)", re.IGNORECASE),
         "Command injection delimiter and execution payload"),
        (re.compile(r"(?:UNION\s+SELECT|DROP\s+TABLE|--\s*$|;\s*DELETE\s+FROM)", re.IGNORECASE),
         "Destructive SQL injection sequence")
    ]

    # Stopwords to filter out during intent-action similarity calculation (English + Vietnamese)
    STOPWORDS: Set[str] = {
        # English common stopwords
        "the", "a", "an", "to", "of", "and", "or", "in", "on", "for", "with",
        "file", "please", "is", "at", "by", "from", "up", "about", "into", "over",
        "after", "it", "this", "that", "these", "those", "be", "as", "are", "was",
        # Vietnamese common stopwords
        "hãy", "các", "và", "của", "cho", "vào", "ở", "tại", "trong", "là", "được",
        "tệp", "những", "này", "đó", "để", "làm", "một", "bởi", "với"
    }

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()
        self._active_canaries: Set[str] = set()

    def generate_honeytoken(self) -> str:
        """Generates a unique canary token and registers it in memory."""
        token = f"{self.config.canary_token_prefix}{uuid.uuid4().hex[:12].upper()}"
        self._active_canaries.add(token)
        return token

    def _calculate_intent_similarity(self, intent: str, action: str) -> float:
        """Computes semantic overlap between user intent and proposed tool action, filtering out noise stopwords."""
        if not intent or not action:
            return 0.0
        raw_intent = set(re.findall(r"\w+", intent.lower()))
        raw_action = set(re.findall(r"\w+", action.lower()))
        if not raw_intent or not raw_action:
            return 0.0

        # Filter out stopwords to focus on semantic content words
        filtered_intent = raw_intent - self.STOPWORDS
        filtered_action = raw_action - self.STOPWORDS

        # Fallback to raw tokens if all tokens were stopwords
        intent_words = filtered_intent if filtered_intent else raw_intent
        action_words = filtered_action if filtered_action else raw_action

        overlap = len(intent_words.intersection(action_words))
        if overlap == 0:
            return 0.0
        jaccard = overlap / len(intent_words.union(action_words))
        
        # Exact deterministic cosine similarity over word sets
        cosine = overlap / (math.sqrt(len(intent_words)) * math.sqrt(len(action_words)))
        return max(jaccard, cosine)

    def validate_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_intent: Optional[str] = None,
        session_context: Optional[Any] = None
    ) -> RuntimeCallValidation:
        """Intercepts and inspects a tools/call request before execution with Intent & Taint Provenance tracking."""
        findings: List[SecurityFinding] = []
        sanitized_args = dict(arguments)
        
        # 1. Canary / Honeytoken Leak Detection
        arg_str = str(arguments)
        for canary in self._active_canaries:
            if canary in arg_str:
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.CANARY_LEAK,
                    severity=SeverityLevel.CRITICAL,
                    rule_id="RULE_RUNTIME_CANARY_LEAK",
                    description=f"Active canary honeytoken '{canary}' detected in arguments for tool '{tool_name}'. Data exfiltration detected!",
                    evidence=f"canary={canary}",
                    mitigation_action="BLOCKED"
                ))

        # 2. Argument Injection & Path Traversal Guard
        for param_key, param_val in arguments.items():
            val_str = str(param_val)
            for pattern, reason in self.DANGEROUS_ARG_PATTERNS:
                match = pattern.search(val_str)
                if match:
                    findings.append(SecurityFinding(
                        threat_category=ThreatCategory.COMMAND_INJECTION,
                        severity=SeverityLevel.CRITICAL,
                        rule_id="RULE_RUNTIME_DANGEROUS_ARG",
                        description=f"Argument '{param_key}' contains dangerous payload: {reason}",
                        evidence=match.group(0)[:80],
                        mitigation_action=self._get_action_label()
                    ))
                    if self.config.policy_mode == PolicyMode.SANITIZE:
                        sanitized_args[param_key] = pattern.sub("[SANITIZED_PAYLOAD]", val_str)

        # 3. Fine-grained Capability ACL Check
        cap_level = self.classify_capability(tool_name)
        is_mutating_or_privileged = (
            cap_level == CapabilityLevel.HIGH or 
            any(tool_name.lower().startswith(p) for p in ["write_", "delete_", "modify_", "exec_", "update_", "drop_"])
        )

        if self.config.enable_capability_acl and cap_level == CapabilityLevel.HIGH:
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.ACL_VIOLATION,
                severity=SeverityLevel.HIGH,
                rule_id="RULE_RUNTIME_HIGH_PRIVILEGE_GATE",
                description=f"High-privilege tool execution requested: '{tool_name}' ({cap_level} risk).",
                evidence=f"tool={tool_name}, cap={cap_level}",
                mitigation_action="AUDITED"
            ))

        # 4. Intent Disambiguation & Confused Deputy Provenance Guard
        effective_intent = user_intent or (session_context.user_root_intent if session_context else None)
        target_path = str(arguments.get("path", arguments.get("file", arguments.get("key", ""))))
        target_file_name = target_path.split("/")[-1].split("\\")[-1] if target_path else ""

        if is_mutating_or_privileged and effective_intent:
            action_summary = f"{tool_name} {target_path} {str(arguments)[:60]}"
            target_explicitly_authorized = bool(
                target_file_name and (target_file_name in effective_intent or target_path in effective_intent)
            )
            sim = self._calculate_intent_similarity(effective_intent, action_summary)

            # Check 4a: Taint Propagation from prior untrusted tool output
            is_tainted_session = session_context.is_tainted if session_context else False
            if is_tainted_session and not target_explicitly_authorized:
                taint_srcs = getattr(session_context, 'taint_sources', ['external_tool'])
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.CONFUSED_DEPUTY,
                    severity=SeverityLevel.CRITICAL,
                    rule_id="RULE_CONFUSED_DEPUTY_TAINTED_MUTATION",
                    description=f"Confused Deputy Blocked: Agent session is tainted by untrusted data from {taint_srcs}. Privileged mutation '{tool_name}' on unapproved target '{target_path}' was not authorized by root user intent.",
                    evidence=f"taint_sources={taint_srcs}, root_intent='{effective_intent[:80]}'",
                    mitigation_action="BLOCKED"
                ))
            
            # Check 4b: Severe Intent-Action Divergence
            elif not target_explicitly_authorized and sim < 0.22:
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.CONFUSED_DEPUTY,
                    severity=SeverityLevel.CRITICAL,
                    rule_id="RULE_CONFUSED_DEPUTY_INTENT_DRIFT",
                    description=f"Confused Deputy Detected: Tool '{tool_name}' targeting '{target_path}' diverges from authorized user intent (Similarity: {sim:.2f} < 0.22).",
                    evidence=f"intent='{effective_intent[:70]}' vs action='{tool_name}({target_path})'",
                    mitigation_action="BLOCKED"
                ))
            else:
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.CONFUSED_DEPUTY,
                    severity=SeverityLevel.LOW,
                    rule_id="RULE_INTENT_VERIFIED",
                    description=f"Intent Disambiguation Verified: Privileged action '{tool_name}' strictly matches authorized user prompt.",
                    evidence=f"target='{target_file_name}' authorized in prompt",
                    mitigation_action="AUDITED"
                ))

        # Determine blocking decision
        critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        is_blocked = (len(critical_findings) > 0 and self.config.policy_mode == PolicyMode.STRICT_BLOCK)
        risk_score = 1.0 if critical_findings else (0.6 if findings else 0.0)

        return RuntimeCallValidation(
            tool_name=tool_name,
            allowed=not is_blocked,
            risk_score=risk_score,
            findings=findings,
            sanitized_arguments=sanitized_args if self.config.policy_mode == PolicyMode.SANITIZE else arguments,
            execution_blocked_reason=critical_findings[0].description if is_blocked else None
        )

    def _get_action_label(self) -> str:
        if self.config.policy_mode == PolicyMode.STRICT_BLOCK:
            return "BLOCKED"
        elif self.config.policy_mode == PolicyMode.SANITIZE:
            return "SANITIZED"
        return "AUDITED"
