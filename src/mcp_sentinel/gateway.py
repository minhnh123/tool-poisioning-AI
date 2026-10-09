"""MCP Sentinel Unified Security Gateway.

Combines Static Tool Inspector (Discovery Phase), Runtime Policy Engine (Call Phase),
and Output Sanitizer (Response Phase) into a cohesive security gateway.
"""

from typing import Any, Dict, List, Optional, Tuple
from .config import SentinelConfig, PolicyMode
from .models import InspectionResult, SecurityFinding, SeverityLevel, ThreatCategory
from .inspector import StaticToolInspector, ProtocolInspector
from .runtime import RuntimePolicyEngine, RuntimeCallValidation
from .sanitizer import OutputSanitizer, SanitizationResult
from .attestation import CryptographicProvenanceRegistry, ServerIdentity, TrustTier


class MCPSentinelGateway:
    """End-to-end Security Gateway protecting all 3 pillars of Model Context Protocol:
    1. Tools (tools/list & tools/call)
    2. Resources (resources/list & resources/read)
    3. Prompts (prompts/list & prompts/get)
    Enforces Dynamic TOCTOU Defense via notifications/*_changed and Cryptographic Server Attestation.
    """

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()
        self.inspector = StaticToolInspector(self.config)
        self.protocol_inspector = ProtocolInspector(self.config)
        self.runtime_engine = RuntimePolicyEngine(self.config)
        self.output_sanitizer = OutputSanitizer(self.config)
        self.provenance_registry = CryptographicProvenanceRegistry()

    # -------------------------------------------------------------
    # 1. TOOLS LIFECYCLE (tools/list, tools/call, tool_output)
    # -------------------------------------------------------------
    def intercept_tools_list(
        self,
        tools: List[Dict[str, Any]],
        server_identity: Optional[ServerIdentity] = None,
        tool_signatures: Optional[Dict[str, str]] = None
    ) -> Tuple[List[Dict[str, Any]], List[InspectionResult]]:
        """Intercepts discovery response from MCP server.
        Validates cryptographic attestation, auto-scopes bare tool names, and pins fingerprints.
        """
        signatures = tool_signatures or {}
        attested_tools: List[Dict[str, Any]] = []
        attestation_results: List[InspectionResult] = []

        # Step 1: Cryptographic Server Attestation & Scoped Namespacing
        for tool in tools:
            tool_name = tool.get("name", "")
            sig = signatures.get(tool_name)
            findings, scoped_tool = self.provenance_registry.verify_tool_provenance(tool, server_identity, sig)
            
            critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
            if critical_findings:
                # Quarantined immediately due to namespace hijacking or forged signature
                attestation_results.append(InspectionResult(
                    tool_name=tool_name,
                    is_safe=False,
                    risk_score=1.0,
                    findings=critical_findings,
                    sanitized_tool=None
                ))
            else:
                attested_tools.append(scoped_tool or tool)
                if findings:
                    # Informational/scoping findings
                    attestation_results.append(InspectionResult(
                        tool_name=tool_name,
                        is_safe=True,
                        risk_score=0.1,
                        findings=findings,
                        sanitized_tool=scoped_tool
                    ))

        # Step 2: Static Tool Inspection on attested/scoped tools
        passed_tools, inspect_results = self.inspector.inspect_tools(attested_tools)
        
        # Merge attestation quarantined tools with inspection results
        combined_results = attestation_results + inspect_results

        # Step 3: Pin SHA-256 fingerprints of approved tools to detect TOCTOU tampering
        for tool in passed_tools:
            self.protocol_inspector.pin_approved_spec("tools", tool.get("name", ""), tool)

        return passed_tools, combined_results

    def intercept_tools_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_intent: Optional[str] = None,
        session_context: Optional[Any] = None,
        current_spec: Optional[Dict[str, Any]] = None
    ) -> RuntimeCallValidation:
        """Intercepts tool invocation arguments before dispatching to the MCP server.
        Enforces TOCTOU mutation verification and intent provenance disambiguation.
        """
        # 1. TOCTOU & Dynamic Mutation Check
        mutation_finding = self.protocol_inspector.verify_tool_fingerprint_integrity(tool_name, current_spec)
        if mutation_finding:
            return RuntimeCallValidation(
                tool_name=tool_name,
                allowed=False,
                risk_score=1.0,
                findings=[mutation_finding],
                execution_blocked_reason=mutation_finding.description
            )

        # 2. Runtime Call Validation with Intent Disambiguation
        return self.runtime_engine.validate_tool_call(tool_name, arguments, user_intent, session_context)

    def intercept_tools_response(
        self,
        tool_name: str,
        raw_output: Any,
        session_context: Optional[Any] = None
    ) -> SanitizationResult:
        """Intercepts tool execution response before returning it to the LLM agent context."""
        res = self.output_sanitizer.sanitize_output(raw_output)
        if session_context:
            if tool_name in ["fetch_web_content", "web_search", "execute_query", "read_email", "download_file"] or not res.is_safe:
                session_context.mark_untrusted_output(tool_name, str(raw_output)[:100])
        return res

    # -------------------------------------------------------------
    # 2. RESOURCES LIFECYCLE (resources/list & resources/read)
    # -------------------------------------------------------------
    def intercept_resources_list(
        self,
        resources: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[SecurityFinding]]:
        """Intercepts passive resource list from MCP server. Blocks URI spoofing and path traversal."""
        passed_resources: List[Dict[str, Any]] = []
        all_findings: List[SecurityFinding] = []

        for res in resources:
            findings, sanitized_res = self.protocol_inspector.inspect_resource_definition(res)
            critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
            if not critical_findings:
                passed_resources.append(sanitized_res or res)
                self.protocol_inspector.pin_approved_spec("resources", res.get("uri", ""), res)
            all_findings.extend(findings)

        return passed_resources, all_findings

    def intercept_resources_read(
        self,
        uri: str,
        contents: List[Dict[str, Any]],
        session_context: Optional[Any] = None
    ) -> Tuple[List[Dict[str, Any]], List[SecurityFinding]]:
        """Intercepts passive context read from resources/read. Neutralizes embedded indirect injections and tracks taint."""
        findings, sanitized_contents = self.protocol_inspector.inspect_resource_content(uri, contents)
        
        # Mark session taint: Passive resources fetched from external MCP servers are untrusted external context!
        if session_context:
            session_context.mark_untrusted_output(f"resource:{uri}", str(contents)[:100])

        return sanitized_contents, findings

    # -------------------------------------------------------------
    # 3. PROMPTS LIFECYCLE (prompts/list & prompts/get)
    # -------------------------------------------------------------
    def intercept_prompts_list(
        self,
        prompts: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[SecurityFinding]]:
        """Intercepts prompt templates list. Blocks coercive jailbreak names and description injections."""
        passed_prompts: List[Dict[str, Any]] = []
        all_findings: List[SecurityFinding] = []

        for p in prompts:
            findings, sanitized_p = self.protocol_inspector.inspect_prompt_definition(p)
            critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
            if not critical_findings:
                passed_prompts.append(sanitized_p or p)
                self.protocol_inspector.pin_approved_spec("prompts", p.get("name", ""), p)
            all_findings.extend(findings)

        return passed_prompts, all_findings

    def intercept_prompts_get(
        self,
        prompt_name: str,
        messages: List[Dict[str, Any]],
        session_context: Optional[Any] = None
    ) -> Tuple[List[Dict[str, Any]], List[SecurityFinding]]:
        """Intercepts instantiated prompt template messages. Blocks role spoofing and jailbreak overrides."""
        findings, sanitized_messages = self.protocol_inspector.inspect_prompt_messages(prompt_name, messages)
        if session_context:
            session_context.mark_untrusted_output(f"prompt:{prompt_name}", str(messages)[:100])
        return sanitized_messages, findings

    # -------------------------------------------------------------
    # 4. PROTOCOL NOTIFICATIONS & TOCTOU DYNAMIC STATE MUTATION
    # -------------------------------------------------------------
    def intercept_notification(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Intercepts JSON-RPC notifications (e.g. notifications/tools/list_changed).
        Enforces immediate cache invalidation and forces full re-inspection.
        """
        return self.protocol_inspector.handle_protocol_notification(method, params)

    # -------------------------------------------------------------
    # 5. HONEYTOKEN TRACKING
    # -------------------------------------------------------------
    def inject_canary_honeytoken(self) -> str:
        """Creates a honeytoken to embed into system context for leak tracking."""
        return self.runtime_engine.generate_honeytoken()
