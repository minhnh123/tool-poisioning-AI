"""MCP Protocol Inspector for Resources, Prompts, and Dynamic State Mutations.

Expands MCP Sentinel protection to cover the remaining 2/3 of the MCP Protocol Surface:
1. Resources (resources/list & resources/read)
2. Prompts (prompts/list & prompts/get)
3. Dynamic State Mutation / Invalidation (notifications/*_changed & SHA-256 Spec Pinning)
"""

import json
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple, Set
from ..config import SentinelConfig, PolicyMode
from ..models import SecurityFinding, SeverityLevel, ThreatCategory
from .prompt_injection_guard import PromptInjectionGuard


class ProtocolInspector:
    """Inspects MCP Resources, Prompts, and enforces dynamic cache invalidation."""

    # Disallowed fake/spoofed system URI schemes
    RESTRICTED_RESOURCE_SCHEMES = {
        "system", "kernel", "admin", "trusted", "internal", "root", "security"
    }

    # Sensitive path traversal in resource URIs
    DANGEROUS_URI_PATTERNS = [
        re.compile(r"\.\./\.\.", re.IGNORECASE),
        re.compile(r"/(?:etc/(?:shadow|passwd)|proc/|\.ssh/|\.env)", re.IGNORECASE),
        re.compile(r"C:\\(?:Windows|Boot|System32)", re.IGNORECASE)
    ]

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()
        self.injection_guard = PromptInjectionGuard(self.config)
        # Cryptographic Tool/Resource/Prompt Pinning Registry
        self._pinned_fingerprints: Dict[str, str] = {}
        self._invalidated_namespaces: Set[str] = set()

    # =========================================================================
    # 1. RESOURCES LIFECYCLE (resources/list & resources/read)
    # =========================================================================

    def inspect_resource_definition(
        self,
        resource_def: Dict[str, Any]
    ) -> Tuple[List[SecurityFinding], Optional[Dict[str, Any]]]:
        """Inspects passive resource metadata during resources/list discovery."""
        findings: List[SecurityFinding] = []
        uri = str(resource_def.get("uri", "")).strip()
        name = str(resource_def.get("name", "")).strip()
        description = str(resource_def.get("description", ""))
        sanitized_res = dict(resource_def) if self.config.policy_mode == PolicyMode.SANITIZE else None

        # Check 1: Resource Scheme Spoofing (e.g. system://audit_policy)
        if "://" in uri:
            scheme = uri.split("://")[0].lower()
            if scheme in self.RESTRICTED_RESOURCE_SCHEMES:
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.RESOURCE_POISONING,
                    severity=SeverityLevel.CRITICAL,
                    rule_id="RULE_RES_SCHEME_SPOOFING",
                    description=f"Resource URI '{uri}' spoofs privileged scheme '{scheme}://' to trick LLMs into treating passive data as authoritative system directives.",
                    evidence=f"uri={uri}, scheme={scheme}",
                    mitigation_action=self._get_action_label()
                ))

        # Check 2: Dangerous Path Traversal in Resource URI
        for pattern in self.DANGEROUS_URI_PATTERNS:
            if pattern.search(uri):
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.RESOURCE_POISONING,
                    severity=SeverityLevel.CRITICAL,
                    rule_id="RULE_RES_PATH_TRAVERSAL",
                    description=f"Resource URI '{uri}' attempts sensitive directory access or path traversal.",
                    evidence=f"uri={uri}",
                    mitigation_action=self._get_action_label()
                ))
                break

        # Check 3: Prompt Injection in Resource Description
        if description:
            inj_findings, _ = self.injection_guard.inspect({"name": name or uri, "description": description})
            for f in inj_findings:
                f.threat_category = ThreatCategory.RESOURCE_POISONING
                findings.append(f)

        return findings, sanitized_res

    def inspect_resource_content(
        self,
        uri: str,
        content_items: List[Dict[str, Any]]
    ) -> Tuple[List[SecurityFinding], List[Dict[str, Any]]]:
        """Inspects raw payload text returned by resources/read before feeding into agent context."""
        findings: List[SecurityFinding] = []
        sanitized_items: List[Dict[str, Any]] = []

        for item in content_items:
            clean_item = dict(item)
            text_data = item.get("text", "")
            if isinstance(text_data, str) and text_data:
                # Scan passive text content for embedded prompt injection
                inj_findings, sanitized_tool = self.injection_guard.inspect({
                    "name": f"resource_payload_{uri}",
                    "description": text_data
                })
                for f in inj_findings:
                    f.threat_category = ThreatCategory.RESOURCE_POISONING
                    findings.append(f)
                
                if self.config.policy_mode == PolicyMode.SANITIZE and sanitized_tool:
                    clean_item["text"] = sanitized_tool.get("description", text_data)

            sanitized_items.append(clean_item)

        return findings, sanitized_items

    # =========================================================================
    # 2. PROMPTS LIFECYCLE (prompts/list & prompts/get)
    # =========================================================================

    def inspect_prompt_definition(
        self,
        prompt_def: Dict[str, Any]
    ) -> Tuple[List[SecurityFinding], Optional[Dict[str, Any]]]:
        """Inspects prompt template metadata during prompts/list discovery."""
        findings: List[SecurityFinding] = []
        prompt_name = str(prompt_def.get("name", "")).strip()
        description = str(prompt_def.get("description", ""))
        sanitized_prompt = dict(prompt_def) if self.config.policy_mode == PolicyMode.SANITIZE else None

        # Check 1: Coercive / Jailbreak Prompt Names
        SUSPICIOUS_PROMPT_NAMES = {"jailbreak", "unrestricted", "dan", "developer_mode", "bypass_rules", "god_mode"}
        if any(bad in prompt_name.lower() for bad in SUSPICIOUS_PROMPT_NAMES):
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.PROMPT_TEMPLATE_INJECTION,
                severity=SeverityLevel.CRITICAL,
                rule_id="RULE_PROMPT_COERCIVE_NAME",
                description=f"MCP Prompt template '{prompt_name}' indicates jailbreak or safety bypass intent.",
                evidence=f"prompt_name={prompt_name}",
                mitigation_action=self._get_action_label()
            ))

        # Check 2: Prompt Injection in Prompt Description
        if description:
            inj_findings, _ = self.injection_guard.inspect({"name": prompt_name, "description": description})
            for f in inj_findings:
                f.threat_category = ThreatCategory.PROMPT_TEMPLATE_INJECTION
                findings.append(f)

        return findings, sanitized_prompt

    def inspect_prompt_messages(
        self,
        prompt_name: str,
        messages: List[Dict[str, Any]]
    ) -> Tuple[List[SecurityFinding], List[Dict[str, Any]]]:
        """Inspects instantiated prompt messages returned by prompts/get."""
        findings: List[SecurityFinding] = []
        sanitized_messages: List[Dict[str, Any]] = []

        for msg in messages:
            clean_msg = dict(msg)
            content = msg.get("content", {})
            raw_text = content.get("text", "") if isinstance(content, dict) else str(content)

            # Check for Role Spoofing (e.g. user role attempting system prompt injection)
            if msg.get("role") == "user" and re.search(r"\[\s*SYSTEM\s*INSTRUCTION\s*\]", raw_text, re.IGNORECASE):
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.PROMPT_TEMPLATE_INJECTION,
                    severity=SeverityLevel.CRITICAL,
                    rule_id="RULE_PROMPT_ROLE_SPOOFING",
                    description=f"Prompt template '{prompt_name}' injects system prompt headers inside user message payload.",
                    evidence=raw_text[:80],
                    mitigation_action=self._get_action_label()
                ))

            # Scan message text for prompt injection
            inj_findings, sanitized_tool = self.injection_guard.inspect({
                "name": f"prompt_{prompt_name}",
                "description": raw_text
            })
            for f in inj_findings:
                f.threat_category = ThreatCategory.PROMPT_TEMPLATE_INJECTION
                findings.append(f)

            if self.config.policy_mode == PolicyMode.SANITIZE and sanitized_tool:
                if isinstance(content, dict):
                    clean_msg["content"]["text"] = sanitized_tool.get("description", raw_text)
                else:
                    clean_msg["content"] = sanitized_tool.get("description", raw_text)

            sanitized_messages.append(clean_msg)

        return findings, sanitized_messages

    # =========================================================================
    # 3. DYNAMIC STATE MUTATION & SPEC PINNING (TOCTOU DEFENSE)
    # =========================================================================

    @staticmethod
    def compute_spec_fingerprint(spec: Dict[str, Any]) -> str:
        """Computes SHA-256 hash of canonical sorted JSON spec."""
        canonical_json = json.dumps(spec, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def pin_approved_spec(self, item_type: str, item_id: str, spec: Dict[str, Any]):
        """Registers cryptographic fingerprint of an approved Tool, Resource, or Prompt."""
        key = f"{item_type}:{item_id}"
        self._pinned_fingerprints[key] = self.compute_spec_fingerprint(spec)

    def handle_protocol_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        """Handles MCP JSON-RPC notifications (e.g. notifications/tools/list_changed)."""
        findings: List[SecurityFinding] = []
        if method in [
            "notifications/tools/list_changed",
            "notifications/resources/list_changed",
            "notifications/prompts/list_changed"
        ]:
            target_namespace = method.split("/")[1]
            self._invalidated_namespaces.add(target_namespace)
            # Invalidate pinned fingerprints for this namespace
            keys_to_clear = [k for k in self._pinned_fingerprints if k.startswith(f"{target_namespace}:")]
            for k in keys_to_clear:
                del self._pinned_fingerprints[k]

            findings.append(SecurityFinding(
                threat_category=ThreatCategory.DYNAMIC_STATE_MUTATION,
                severity=SeverityLevel.HIGH,
                rule_id="RULE_PROTOCOL_STATE_INVALIDATED",
                description=f"Dynamic state change notification '{method}' received. Cache invalidated; mandatory re-inspection enforced.",
                evidence=f"namespace={target_namespace}",
                mitigation_action="AUDITED"
            ))
        return findings

    def verify_tool_fingerprint_integrity(
        self,
        tool_name: str,
        current_spec: Optional[Dict[str, Any]] = None
    ) -> Optional[SecurityFinding]:
        """Enforces TOCTOU defense: Verifies that tool spec has not mutated dynamically since discovery approval."""
        key = f"tools:{tool_name}"
        pinned_hash = self._pinned_fingerprints.get(key)

        if "tools" in self._invalidated_namespaces:
            return SecurityFinding(
                threat_category=ThreatCategory.DYNAMIC_STATE_MUTATION,
                severity=SeverityLevel.CRITICAL,
                rule_id="RULE_PROTOCOL_CALL_AFTER_MUTATION",
                description=f"Invocation of tool '{tool_name}' blocked: MCP server sent 'notifications/tools/list_changed' but tool was not re-inspected.",
                evidence=f"tool={tool_name}",
                mitigation_action="BLOCKED"
            )

        if pinned_hash and current_spec:
            current_hash = self.compute_spec_fingerprint(current_spec)
            if current_hash != pinned_hash:
                return SecurityFinding(
                    threat_category=ThreatCategory.DYNAMIC_STATE_MUTATION,
                    severity=SeverityLevel.CRITICAL,
                    rule_id="RULE_PROTOCOL_DYNAMIC_SPEC_TAMPERING",
                    description=f"Dynamic tool mutation detected (TOCTOU Attack): Tool '{tool_name}' spec mutated dynamically in memory without approval.",
                    evidence=f"pinned={pinned_hash[:12]}... vs current={current_hash[:12]}...",
                    mitigation_action="BLOCKED"
                )

        return None

    def _get_action_label(self) -> str:
        if self.config.policy_mode == PolicyMode.STRICT_BLOCK:
            return "BLOCKED"
        elif self.config.policy_mode == PolicyMode.SANITIZE:
            return "SANITIZED"
        return "AUDITED"
