# 🏛️ MCP Sentinel — Architecture & Security Specifications

This document outlines the internal architecture, threat modeling, and defense mechanisms of **MCP Sentinel**.

---

## 1. High-Level Architecture Overview

MCP Sentinel functions as an inline, zero-trust security gateway between the AI Agent (Host) and upstream MCP Tool Servers:

```
+-------------------------------------------------------------------+
|                            AI AGENT / LLM                         |
+-------------------------------------------------------------------+
                                  |
                                  | MCP Protocol JSON-RPC
                                  v
+===================================================================+
|                        MCP SENTINEL GATEWAY                       |
|                                                                   |
|  [Phase 1: Discovery (tools/list)]                                |
|  - Cryptographic Attestation & Namespace Registry                 |
|  - Prompt Injection Guard (Unicode, Leet, Base64, Tags)           |
|  - Tool Squatting Detector (Levenshtein & Prefix distance)        |
|  - Semantic Anomaly Detector (Sentence-Transformers)              |
|  - Spec Fingerprint Pinning (Anti-TOCTOU)                         |
|                                                                   |
|  [Phase 2: Call Interception (tools/call)]                        |
|  - Capability ACL Gatekeeper (HIGH / MEDIUM / LOW)                |
|  - Honeytoken / Canary Leak Verification                          |
|  - Intent Disambiguation & Confused Deputy Drift Guard            |
|  - Dangerous Argument & Path Traversal Sanitization               |
|                                                                   |
|  [Phase 3: Response Verification (tool_output)]                   |
|  - Indirect Prompt Injection Defense                              |
|  - Dynamic Session Taint Provenance Tracker                       |
+===================================================================+
                                  |
                                  | Filtered & Sanitized RPC
                                  v
+-------------------------------------------------------------------+
|                        UPSTREAM MCP SERVERS                       |
+-------------------------------------------------------------------+
```

---

## 2. The 3-Phase Defense Lifecycle

### Phase 1: Discovery Phase (`tools/list`)
- **Namespace Attestation**: Ensures each tool belongs to an authorized MCP server identity. Auto-scopes bare tool names to prevent tool shadowing.
- **Prompt Injection & Docstring Poisoning**:
  - Detects bracketed override directives (`[SYSTEM INSTRUCTION: ...]`).
  - Detects XML-style tags (`<instruction>`, `<system>`).
  - Detects invisible Unicode Tag smuggling (`U+E0000` block).
  - Normalizes and detects Leet-speak obfuscation (`1GN0R3`).
  - Unpacks single and double/nested Base64 encoded commands.
- **Tool Squatting**: Prevents typosquatting impersonation of standard ecosystem tools (`read_fi1e`, `write_f1le`).
- **TOCTOU Defense**: Pins SHA-256 fingerprints upon approval; detects out-of-band runtime tool spec mutation.

### Phase 2: Call Interception Phase (`tools/call`)
- **Capability ACL**: Classifies tools into `HIGH`, `MEDIUM`, and `LOW` risk tiers via exact maps and prefix heuristics (`exec_`, `write_`, `delete_`, `drop_`).
- **Intent Disambiguation**: Compares the user's root prompt intent with the tool call action summary. Blocks unprompted privileged mutations.
- **Canary Leak Tracking**: Intercepts canary tokens leaking into external exfiltration tool arguments.

### Phase 3: Response Verification Phase (`tool_output`)
- **Indirect Injection Scanning**: Inspects returned web page content, database queries, and file contents.
- **Taint Provenance**: When untrusted data is ingested, flags the active agent session as `tainted`. Blocks downstream chained file or shell writes without explicit user approval.

---

## 3. Latency & Performance Engineering

Each inspection module is profiled individually:
- `PromptInjectionGuard`: ~0.20 ms
- `SchemaValidator`: ~0.01 ms
- `ToolSquattingDetector`: ~0.05 ms
- `SemanticAnomalyDetector`: Cached vector similarity
- **Total Gateway Median Latency (P50)**: **12.45 ms**
