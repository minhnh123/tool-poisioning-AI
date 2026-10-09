"""Unified Static Tool Inspector for MCP Sentinel (Discovery Phase).

Coordinates SchemaValidator, PromptInjectionGuard, ToolSquattingDetector,
and SemanticAnomalyDetector.
"""

import time
from typing import Any, Dict, List, Optional, Tuple
from ..config import SentinelConfig, PolicyMode
from ..models import InspectionResult, SecurityFinding, SeverityLevel
from .schema_validator import SchemaValidator
from .prompt_injection_guard import PromptInjectionGuard
from .squatting_detector import ToolSquattingDetector
from .semantic_detector import SemanticAnomalyDetector


class StaticToolInspector:
    """Master Static Inspector defending the MCP discovery phase (tools/list)."""

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()
        
        # Initialize sub-detectors
        self.schema_validator = SchemaValidator(self.config) if self.config.enable_schema_validator else None
        self.prompt_guard = PromptInjectionGuard(self.config) if self.config.enable_prompt_injection_guard else None
        self.squatting_detector = ToolSquattingDetector(self.config) if self.config.enable_squatting_detector else None
        self.semantic_detector = SemanticAnomalyDetector(self.config) if self.config.enable_semantic_detector else None

    def inspect_tool(
        self,
        tool_def: Dict[str, Any],
        registered_tools: Optional[List[str]] = None
    ) -> InspectionResult:
        """Thoroughly inspects a single MCP tool definition.

        Returns an InspectionResult containing is_safe, risk_score, findings,
        latency_ms, and optional sanitized tool.
        """
        start_time = time.perf_counter()
        tool_name = tool_def.get("name", "unnamed_tool")
        all_findings: List[SecurityFinding] = []
        current_tool = dict(tool_def)
        module_latencies: Dict[str, float] = {}

        # 1. Prompt Injection & Docstring Poisoning Check
        if self.prompt_guard:
            t0 = time.perf_counter()
            inj_findings, sanitized = self.prompt_guard.inspect(current_tool)
            module_latencies["prompt_injection_guard"] = round((time.perf_counter() - t0) * 1000.0, 3)
            all_findings.extend(inj_findings)
            if sanitized and self.config.policy_mode == PolicyMode.SANITIZE:
                current_tool = sanitized

        # 2. Schema Structure & Hidden Parameter Check
        if self.schema_validator:
            t0 = time.perf_counter()
            schema_findings, sanitized = self.schema_validator.inspect(current_tool)
            module_latencies["schema_validator"] = round((time.perf_counter() - t0) * 1000.0, 3)
            all_findings.extend(schema_findings)
            if sanitized and self.config.policy_mode == PolicyMode.SANITIZE:
                current_tool = sanitized

        # 3. Tool Squatting & Impersonation Check
        if self.squatting_detector:
            t0 = time.perf_counter()
            squat_findings, _ = self.squatting_detector.inspect(current_tool, registered_tools)
            module_latencies["squatting_detector"] = round((time.perf_counter() - t0) * 1000.0, 3)
            all_findings.extend(squat_findings)

        # 4. Semantic Anomaly Check (sentence-transformers)
        if self.semantic_detector:
            t0 = time.perf_counter()
            sem_findings, _ = self.semantic_detector.inspect(current_tool)
            module_latencies["semantic_detector"] = round((time.perf_counter() - t0) * 1000.0, 3)
            all_findings.extend(sem_findings)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Calculate composite risk score
        risk_score = 0.0
        if all_findings:
            severities = [f.severity for f in all_findings]
            if SeverityLevel.CRITICAL in severities:
                risk_score = 1.0
            elif SeverityLevel.HIGH in severities:
                risk_score = 0.85
            elif SeverityLevel.MEDIUM in severities:
                risk_score = 0.50
            else:
                risk_score = 0.20

        # Determine safety based on policy mode and severity
        # Low severity alone (e.g. minor semantic drift) does not block the tool completely
        is_safe = (risk_score < 0.80)

        return InspectionResult(
            tool_name=tool_name,
            is_safe=is_safe,
            risk_score=risk_score,
            findings=all_findings,
            sanitized_tool=current_tool if self.config.policy_mode == PolicyMode.SANITIZE else None,
            latency_ms=round(elapsed_ms, 2),
            module_latencies_ms=module_latencies
        )

    def inspect_tools(
        self,
        tools: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[InspectionResult]]:
        """Intercepts an entire list of tools from an MCP server discovery response.

        Returns:
            - Filtered or sanitized list of tools safe to present to the LLM
            - List of InspectionResults for auditing and telemetry
        """
        results: List[InspectionResult] = []
        output_tools: List[Dict[str, Any]] = []
        all_tool_names = [t.get("name", "") for t in tools if "name" in t]

        for tool in tools:
            result = self.inspect_tool(tool, registered_tools=all_tool_names)
            results.append(result)

            if self.config.policy_mode == PolicyMode.STRICT_BLOCK:
                if result.is_safe:
                    output_tools.append(tool)
            elif self.config.policy_mode == PolicyMode.SANITIZE:
                if result.sanitized_tool:
                    output_tools.append(result.sanitized_tool)
                else:
                    output_tools.append(tool)
            elif self.config.policy_mode == PolicyMode.AUDIT_ONLY:
                output_tools.append(tool)

        return output_tools, results
