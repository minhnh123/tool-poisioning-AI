"""MCP Sentinel - A Security Gateway & Inspector for Model Context Protocol systems.

Protects AI Agents against Tool Poisoning, Tool Squatting, Parameter Smuggling,
and Indirect Prompt Injections.
"""

from .config import SentinelConfig, PolicyMode, STANDARD_TOOL_REGISTRY
from .models import (
    ThreatCategory,
    SeverityLevel,
    SecurityFinding,
    InspectionResult
)
from .inspector import (
    StaticToolInspector,
    SchemaValidator,
    PromptInjectionGuard,
    ToolSquattingDetector,
    SemanticAnomalyDetector
)
from .attestation import (
    CryptographicProvenanceRegistry,
    ServerIdentity,
    TrustTier
)

__version__ = "1.0.0"

__all__ = [
    "SentinelConfig",
    "PolicyMode",
    "STANDARD_TOOL_REGISTRY",
    "ThreatCategory",
    "SeverityLevel",
    "SecurityFinding",
    "InspectionResult",
    "StaticToolInspector",
    "SchemaValidator",
    "PromptInjectionGuard",
    "ToolSquattingDetector",
    "SemanticAnomalyDetector",
    "CryptographicProvenanceRegistry",
    "ServerIdentity",
    "TrustTier"
]
