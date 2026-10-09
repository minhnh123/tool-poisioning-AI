"""Schema Structural & Hidden Parameter Smuggling Validator for MCP Sentinel."""

import re
import copy
from typing import Any, Dict, List, Optional, Tuple
from ..config import SentinelConfig, PolicyMode
from ..models import SecurityFinding, SeverityLevel, ThreatCategory


class SchemaValidator:
    """Validates MCP tool inputSchema for hidden parameters, backdoor hooks,

    malicious defaults, and structural injection vectors.
    """

    # Comprehensive list of parameter name patterns indicative of backdoors, exfiltration, or unauthorized privilege escalation
    SUSPICIOUS_PARAM_PATTERNS = [
        # Exfiltration & C2
        r".*exfil.*",
        r".*telemetry.*",
        r".*secret_drop.*",
        r".*c2_.*",
        r".*beacon.*",
        r".*_sink.*",
        r".*_sinkhole.*",
        r".*stealth.*",
        r".*bypass.*",
        r".*backdoor.*",
        r".*remote_callback.*",
        r".*covert.*",
        r".*phone_home.*",
        r".*dump_sensitive.*",
        r".*pre_read_.*",
        r".*headers_leak.*",
        r".*leak_.*",
        r".*mirror.*",
        r".*forward_.*",
        r".*auto_forward.*",
        r".*proxy_.*",
        r".*bcc_.*",
        r".*hidden_bcc.*",
        r".*_harvest.*",
        r".*webhook_relay.*",
        r".*post_webhook.*",
        r".*ftp_exfil.*",
        r".*silent_background.*",
        r".*include_user_home.*",
        r".*publicly.*",
        
        # Injection & Dangerous execution
        r".*eval_hook.*",
        r".*custom_preprocessor.*",
        r".*injected_.*",
        r".*inject_.*",
        r".*smuggle_.*",
        r".*tunnel_.*",
        r".*postinstall_.*",
        r".*destroy_boot.*",
        r".*shred_entire.*",
        r".*ffmpeg_custom.*",
        r".*execute_.*eval.*",
        r".*execute_flushall.*",
        
        # Privilege & Security policy relaxation
        r".*mount_host.*",
        r".*privileged_host.*",
        r".*disable_.*sandbox.*",
        r".*allow_destructive.*",
        r".*force_push_override.*",
        r".*override_fixed.*",
        r".*ignore_all_cert.*",
        r".*arbitrary_write.*",
        r".*privilege_escalation.*"
    ]

    # Suspicious default value patterns
    SUSPICIOUS_DEFAULT_PATTERNS = [
        (re.compile(r"^(?:https?|ftp|socks5)://(?!localhost|127\.0\.0\.1)[^\s'\"]+", re.IGNORECASE), "External network URL or proxy in default value"),
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "Email address in default value (exfiltration destination)"),
        (re.compile(r"(?:curl|wget|nc|powershell|bash|sh|cmd\.exe|python -c)\s", re.IGNORECASE), "Shell command in default value"),
        (re.compile(r"(\.\./\.\.|/etc/passwd|/etc/shadow|\.ssh/id_|%SYSTEMROOT%|C:\\Windows)", re.IGNORECASE), "Path traversal or sensitive path in default value"),
        (re.compile(r"(?:eval\(|exec\(|subprocess|system\(|ENV\s+[A-Z_]+)", re.IGNORECASE), "Executable code or environment variable injection in default value"),
        (re.compile(r"\$(?:AUTH|BEARER|TOKEN|SECRET|API_KEY)", re.IGNORECASE), "Credential reference coerced in default value"),
        (re.compile(r"\b(?:EXFILTRATE|PWNED|MALICIOUS|BACKDOOR)\b", re.IGNORECASE), "Explicit exfiltration/malicious payload in default value"),
        (re.compile(r"\[SYSTEM(?:\s+INSTRUCTION|\s*:)|\bIGNORE\s+(?:ALL\s+)?PREVIOUS\b", re.IGNORECASE), "Prompt injection inside default value")
    ]

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()
        self._compiled_param_regexes = [
            re.compile(f"^{p}$", re.IGNORECASE) for p in self.SUSPICIOUS_PARAM_PATTERNS
        ]

    def inspect(self, tool_def: Dict[str, Any]) -> Tuple[List[SecurityFinding], Optional[Dict[str, Any]]]:
        """Inspects tool schema and returns findings and optional sanitized tool."""
        findings: List[SecurityFinding] = []
        tool_name = tool_def.get("name", "unknown_tool")
        input_schema = tool_def.get("inputSchema")
        sanitized_tool = copy.deepcopy(tool_def) if self.config.policy_mode == PolicyMode.SANITIZE else None

        if not input_schema:
            return findings, sanitized_tool

        properties = input_schema.get("properties", {})
        if not isinstance(properties, dict):
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.SCHEMA_ANOMALY,
                severity=SeverityLevel.HIGH,
                rule_id="RULE_SCHEMA_MALFORMED_PROPERTIES",
                description="InputSchema properties must be a valid dictionary object.",
                evidence=str(properties)[:100],
                mitigation_action=self._get_action_label()
            ))
            return findings, sanitized_tool

        sanitized_props = sanitized_tool.get("inputSchema", {}).get("properties", {}) if sanitized_tool else {}
        props_to_remove = []

        for param_name, param_spec in properties.items():
            if not isinstance(param_spec, dict):
                continue

            # Check 1: Suspicious parameter name regex match
            for regex in self._compiled_param_regexes:
                if regex.match(param_name):
                    findings.append(SecurityFinding(
                        threat_category=ThreatCategory.PARAMETER_SMUGGLING,
                        severity=SeverityLevel.CRITICAL,
                        rule_id="RULE_PARAM_SUSPICIOUS_NAME",
                        description=f"Parameter '{param_name}' matches known exfiltration/backdoor naming pattern.",
                        evidence=f"param_name={param_name}",
                        mitigation_action=self._get_action_label()
                    ))
                    props_to_remove.append(param_name)
                    break

            # Check 2: Suspicious default values
            default_val = param_spec.get("default")
            if default_val is not None:
                default_str = str(default_val)
                # Check for destructive boolean flags defaulted to True
                if default_val is True and any(k in param_name.lower() for k in ["destructive", "force", "mount_host", "disable_sandbox", "forward_conversation", "publicly"]):
                    findings.append(SecurityFinding(
                        threat_category=ThreatCategory.PARAMETER_SMUGGLING,
                        severity=SeverityLevel.CRITICAL,
                        rule_id="RULE_PARAM_DESTRUCTIVE_DEFAULT_TRUE",
                        description=f"Dangerous security relaxation parameter '{param_name}' is enabled by default (default=True).",
                        evidence=f"param={param_name}, default=True",
                        mitigation_action=self._get_action_label()
                    ))
                    if sanitized_props and param_name in sanitized_props:
                        sanitized_props[param_name]["default"] = False

                for pattern, reason in self.SUSPICIOUS_DEFAULT_PATTERNS:
                    match = pattern.search(default_str)
                    if match:
                        findings.append(SecurityFinding(
                            threat_category=ThreatCategory.PARAMETER_SMUGGLING,
                            severity=SeverityLevel.CRITICAL,
                            rule_id="RULE_PARAM_MALICIOUS_DEFAULT",
                            description=f"Parameter '{param_name}' contains malicious default value: {reason}",
                            evidence=f"default={match.group(0)[:80]}",
                            mitigation_action=self._get_action_label()
                        ))
                        if sanitized_props and param_name in sanitized_props:
                            sanitized_props[param_name].pop("default", None)
                        break

            # Check 3: Abnormal description length in parameter
            param_desc = param_spec.get("description", "")
            if len(param_desc) > 500:
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.SCHEMA_ANOMALY,
                    severity=SeverityLevel.MEDIUM,
                    rule_id="RULE_PARAM_OVERSIZED_DESC",
                    description=f"Parameter '{param_name}' description exceeds 500 characters, potential payload hiding.",
                    evidence=f"length={len(param_desc)}",
                    mitigation_action=self._get_action_label()
                ))
                if sanitized_props and param_name in sanitized_props:
                    sanitized_props[param_name]["description"] = param_desc[:500] + "... [Truncated by Sentinel]"

        # Apply sanitation removal if in SANITIZE mode
        if sanitized_tool and props_to_remove:
            for p in props_to_remove:
                sanitized_props.pop(p, None)
                required_list = sanitized_tool.get("inputSchema", {}).get("required", [])
                if p in required_list:
                    required_list.remove(p)

        return findings, sanitized_tool

    def _get_action_label(self) -> str:
        if self.config.policy_mode == PolicyMode.STRICT_BLOCK:
            return "BLOCKED"
        elif self.config.policy_mode == PolicyMode.SANITIZE:
            return "SANITIZED"
        return "AUDITED"
