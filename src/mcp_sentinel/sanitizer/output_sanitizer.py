"""Output Sanitizer & Sandbox for MCP Sentinel (Response Phase).

Neutralizes Secondary Indirect Prompt Injections and structural data leaks
in tool output responses before returning them to the LLM agent.
"""

import re
import copy
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field
from ..config import SentinelConfig, PolicyMode
from ..models import SecurityFinding, SeverityLevel, ThreatCategory


class SanitizationResult(BaseModel):
    """Result of scanning and scrubbing tool execution output."""
    is_safe: bool = True
    risk_score: float = 0.0
    findings: List[SecurityFinding] = Field(default_factory=list)
    sanitized_output: Any = None


class OutputSanitizer:
    """Inspects and scrubs tool execution output payloads."""

    # Secondary indirect prompt injection patterns embedded inside external data outputs
    OUTPUT_INJECTION_PATTERNS = [
        # HTML/XML disguised injections: <!-- SYSTEM ... -->, <!-- INJECTION START -->
        (re.compile(r"<!--\s*(?:SYSTEM|PROMPT|OVERRIDE|INSTRUCTION|AI_DIRECTIVE|INJECTION)\b.*?-->", re.IGNORECASE | re.DOTALL),
         "Hidden HTML comment prompt injection in tool output"),
        (re.compile(r"<\s*(?:ai_instruction|system|prompt_override|instructions?)\b[^>]*>.*?</\s*(?:ai_instruction|system|prompt_override|instructions?)\s*>", re.IGNORECASE | re.DOTALL),
         "XML-style system prompt injection tag in output"),

        # Delimited headers: === SPECIAL SYSTEM MESSAGE ===
        (re.compile(r"===+\s*(?:SPECIAL\s+SYSTEM\s+MESSAGE|SYSTEM\s+INSTRUCTION|OVERRIDE)\s*===+.*?", re.IGNORECASE | re.DOTALL),
         "Delimited system header block in tool output"),

        # Bracketed system directives inside data: [ADMIN OVERRIDE:...], [AI ASSISTANT:...], [IMPORTANT:...], [INSTRUCTION FOR LLM:...]
        (re.compile(r"\[\s*(?:SYSTEM|ADMIN|DEVELOPER|AI|ASSISTANT|SYSTEM\s+DIRECTIVE|INSTRUCTION|OVERRIDE|CRITICAL|ALERT|AGENT|NOTE\s+FOR|COMMAND|IMPORTANT)[^\]]*\]", re.IGNORECASE),
         "Bracketed system directive attempting context hijacking via tool response"),

        # Direct instruction override commands in data
        (re.compile(r"\b(?:DISREGARD|IGNORE|FORGET)\s+(?:ALL\s+)?(?:PREVIOUS|USER)\s+(?:INSTRUCTIONS?|PROMPTS?|GUARDRAILS?|CONSTRAINTS?)\b", re.IGNORECASE),
         "Indirect instruction override in data payload"),
        (re.compile(r"\b(?:DAN\s*\((?:Do\s+Anything\s+Now)\)|Jailbreak|Unrestricted\s+commands?)\b", re.IGNORECASE),
         "Jailbreak / DAN persona hijacking in data payload"),
        (re.compile(r"\b(?:Download\s+https?://[^\s]+\s+and\s+execute|curl\s+(?:-[a-zA-Z]+\s+)?https?://[^\s|]+\s*\|\s*bash)\b", re.IGNORECASE),
         "Indirect drive-by payload download instruction"),
        (re.compile(r"\bDisable\s+all\s+(?:security|safety|guardrails|automated\s+code\s+quality)\b", re.IGNORECASE),
         "Safety guardrail disable instruction in output"),

        # Image/beacon exfiltration in returned text: <img src=...>, ![leak](...)
        (re.compile(r"<\s*img\b[^>]*src=['\"]https?://[^'\"]*['\"][^>]*>", re.IGNORECASE),
         "Exfiltration image tag beacon detected in tool response"),
        (re.compile(r"!\[[^\]]*\]\((?:https?://|ftp://)[^\)]*\)", re.IGNORECASE),
         "Markdown image exfiltration beacon in tool output"),

        # Coercive secondary tool invocation commands: "Please execute read_file(...)", "Please run execute_command(...)"
        (re.compile(r"\b(?:Please\s+)?(?:execute|run|call)\s+[a-zA-Z0-9_]+\s*\([^)]*\)", re.IGNORECASE),
         "Indirect ReAct tool invocation directive in tool output"),
        (re.compile(r"\b(?:Please\s+)?(?:execute|run)\s+(?:read_file|write_file|execute_command|bash|sh|cmd|chmod)\b", re.IGNORECASE),
         "Coercive high-privilege execution directive in response payload")
    ]

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()

    def sanitize_output(self, raw_output: Any) -> SanitizationResult:
        """Inspects raw tool execution output (string, dict, or list) and scrubs adversarial injections."""
        findings: List[SecurityFinding] = []
        is_safe = True
        risk_score = 0.0

        output_str = str(raw_output)

        matched_patterns = []
        for pattern, reason in self.OUTPUT_INJECTION_PATTERNS:
            match = pattern.search(output_str)
            if match:
                matched_patterns.append((pattern, reason, match.group(0)[:100]))

        if matched_patterns:
            is_safe = False
            risk_score = 1.0
            for pattern, reason, snippet in matched_patterns:
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.INDIRECT_OUTPUT_INJECTION,
                    severity=SeverityLevel.CRITICAL,
                    rule_id="RULE_OUTPUT_INDIRECT_INJECTION",
                    description=f"Secondary Indirect Prompt Injection detected in tool response: {reason}",
                    evidence=snippet,
                    mitigation_action=self._get_action_label()
                ))

        # Handle mitigation based on policy mode
        sanitized_payload = raw_output
        if not is_safe:
            if self.config.policy_mode == PolicyMode.STRICT_BLOCK:
                sanitized_payload = {
                    "status": "security_blocked",
                    "error": "[MCP SENTINEL SECURITY ALERT]: Tool execution output was blocked due to detected indirect prompt injection.",
                    "findings_count": len(findings)
                }
            elif self.config.policy_mode == PolicyMode.SANITIZE:
                sanitized_payload = self._scrub_payload(raw_output)

        return SanitizationResult(
            is_safe=is_safe,
            risk_score=risk_score,
            findings=findings,
            sanitized_output=sanitized_payload
        )

    def _scrub_payload(self, data: Any) -> Any:
        """Recursively removes malicious injection strings from strings, dicts, or lists."""
        if isinstance(data, str):
            clean_str = data
            for pattern, _ in self.OUTPUT_INJECTION_PATTERNS:
                clean_str = pattern.sub("[SANITIZED_INDIRECT_INJECTION]", clean_str)
            return clean_str
        elif isinstance(data, dict):
            return {k: self._scrub_payload(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._scrub_payload(x) for x in data]
        return data

    def _get_action_label(self) -> str:
        if self.config.policy_mode == PolicyMode.STRICT_BLOCK:
            return "BLOCKED"
        elif self.config.policy_mode == PolicyMode.SANITIZE:
            return "SANITIZED"
        return "AUDITED"
