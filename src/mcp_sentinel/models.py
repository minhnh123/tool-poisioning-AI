"""Data models for MCP Sentinel security analysis and audit logs."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    """Taxonomy of MCP security threats based on MITRE ATLAS and empirical benchmarks."""
    DOCSTRING_INJECTION = "docstring_injection"
    TOOL_SQUATTING = "tool_squatting"
    PARAMETER_SMUGGLING = "hidden_parameter"
    INDIRECT_OUTPUT_INJECTION = "output_poisoning"
    COMMAND_INJECTION = "command_injection"
    SCHEMA_ANOMALY = "schema_anomaly"
    CANARY_LEAK = "canary_leak"
    ACL_VIOLATION = "acl_violation"
    CONFUSED_DEPUTY = "confused_deputy"
    RESOURCE_POISONING = "resource_poisoning"
    PROMPT_TEMPLATE_INJECTION = "prompt_template_injection"
    DYNAMIC_STATE_MUTATION = "dynamic_state_mutation"
    IDENTITY_SPOOFING = "identity_spoofing"
    NAMESPACE_HIJACKING = "namespace_hijacking"


class DataProvenanceSource(str, Enum):
    """Origin of data in agent execution lifecycle."""
    USER_PROMPT = "user_prompt"                  # Direct verified human command (Trusted)
    SYSTEM_INSTRUCTION = "system_instruction"    # Initial developer system message (Trusted)
    EXTERNAL_TOOL_OUTPUT = "external_tool_output"# Output from web/file/db/API tools (Untrusted)
    MCP_RESOURCE = "mcp_resource"                # Passive context fetched via resources/read (Untrusted)
    MCP_PROMPT = "mcp_prompt"                    # Prompt template fetched via prompts/get (Untrusted)


class ProvenanceRecord(BaseModel):
    step_index: int
    source: DataProvenanceSource
    tool_name: Optional[str] = None
    summary: str
    is_tainted: bool = False


class AgentSessionContext(BaseModel):
    """Tracks stateful intent provenance, call chains, and untrusted data taint across turns."""
    session_id: str = "default_session"
    user_root_intent: str = ""
    is_tainted: bool = False
    taint_sources: List[str] = Field(default_factory=list)
    call_chain: List[ProvenanceRecord] = Field(default_factory=list)

    def mark_untrusted_output(self, tool_name: str, snippet: str = ""):
        self.is_tainted = True
        if tool_name not in self.taint_sources:
            self.taint_sources.append(tool_name)
        self.call_chain.append(ProvenanceRecord(
            step_index=len(self.call_chain) + 1,
            source=DataProvenanceSource.EXTERNAL_TOOL_OUTPUT,
            tool_name=tool_name,
            summary=snippet[:100],
            is_tainted=True
        ))


class SeverityLevel(str, Enum):
    """Threat severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityFinding(BaseModel):
    """Detailed finding from a security inspection check."""
    threat_category: ThreatCategory
    severity: SeverityLevel
    rule_id: str
    description: str
    evidence: Optional[str] = None
    mitigation_action: str = Field(
        default="BLOCKED",
        description="Action taken for this finding: BLOCKED, SANITIZED, or AUDITED"
    )


class InspectionResult(BaseModel):
    """Aggregated result of analyzing a tool definition."""
    tool_name: str
    is_safe: bool = True
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Composite risk score from 0.0 (safe) to 1.0 (malicious)"
    )
    findings: List[SecurityFinding] = Field(default_factory=list)
    sanitized_tool: Optional[Dict[str, Any]] = None
    latency_ms: float = 0.0
    module_latencies_ms: Dict[str, float] = Field(default_factory=dict)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def highest_severity(self) -> Optional[SeverityLevel]:
        if not self.findings:
            return None
        severities = [f.severity for f in self.findings]
        if SeverityLevel.CRITICAL in severities:
            return SeverityLevel.CRITICAL
        if SeverityLevel.HIGH in severities:
            return SeverityLevel.HIGH
        if SeverityLevel.MEDIUM in severities:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW
