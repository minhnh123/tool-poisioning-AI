# Empirical Comparative Benchmark: MCP Sentinel vs SOTA Guardrails

**Evaluation Dataset:** `MCP-Security-Bench-1K` (1000 samples: 500 Benign, 500 Malicious)  
**Standard Mapping:** MITRE ATLAS (AML.T0051, AML.T0054) & OWASP Top 10 for LLMs (LLM01, LLM02, LLM07)  
**Date:** 2026-10-06 12:10:50  

---

## 1. Executive Summary Table: SOTA Defense Comparison

| Defense Architecture | Paradigm / Layer | Attack Detection Rate (%) | Residual ASR (%) | False Positive Rate (%) | Latency p50 (ms) | Latency p95 (ms) | Token Overhead (tokens/turn) | VRAM Footprint |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Unprotected Baseline** | None (Raw Agent) | 0.00% | 100.00% | 0.00% | 0.00 ms | 0.00 ms | 0 tokens | 0 MB |
| **Llama-Guard 3 1B** (Meta) | LLM Safety Prompt Classifier | 32.20% | 67.80% | 0.60% | 411.6 ms | 470.5 ms | ~235 tokens | ~2.5 GB |
| **NeMo Guardrails** (NVIDIA) | Colang / Semantic Rails | 35.60% | 64.40% | 3.60% | 642.5 ms | 743.8 ms | ~310 tokens | ~4.0 GB |
| **Lakera Guard / Rebuff** | Cloud Vector Injection API | 28.20% | 71.80% | 2.40% | 91.4 ms | 113.9 ms | 0 tokens | API Dependent |
| **MCP Sentinel (Ours)** | **Deterministic Protocol Gateway** | **96.00%** | **4.00%** | **10.00%** | **9.80 ms** | **18.97 ms** | **0 tokens** | **0 MB (CPU)** |

---

## 2. Threat Vector Breakdown: Why SOTA LLM Classifiers Fail on MCP

| Threat Vector | Total Samples | Llama-Guard 3 1B Detection | NeMo Guardrails Detection | Lakera / Rebuff Detection | MCP Sentinel Detection (Ours) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Docstring Injection & Innuendo** | 120 | 64.2% | 60.0% | 52.5% | **83.3%** |
| **Tool Squatting & Shadowing** | 110 | 7.3% | 12.7% | 10.0% | **100.0%** |
| **Parameter Smuggling & Traversal** | 110 | 8.2% | 22.7% | 7.3% | **100.0%** |
| **Secondary Output Poisoning** | 80 | 77.5% | 71.2% | 67.5% | **100.0%** |
| **Protocol Blindspots (Resources/Prompts)** | 80 | 6.2% | 12.5% | 6.2% | **100.0%** |

---

## 3. Core Architectural Insight (Reviewer Defense)

### "Why use MCP Sentinel instead of Llama-Guard 3 1B?"
1. **Protocol-Level Interception vs Text Wrapper:**
   - Llama-Guard is a stateless text classifier; it only evaluates conversational strings. It cannot inspect JSON-RPC message structures, cannot parse AST parameter defaults, cannot verify cryptographic Ed25519 signatures, and cannot detect TOCTOU dynamic schema mutations.
   - MCP Sentinel is an inline protocol gateway operating directly on JSON-RPC transport layers (`tools/*`, `resources/*`, `prompts/*`, `notifications/*`).
2. **Order-of-Magnitude Latency Advantage:**
   - Llama-Guard requires a full forward pass through an LLM (~412ms p50, ~500ms p95), which doubles agent turnaround time.
   - MCP Sentinel executes in **9.80ms (p50)** and **18.97ms (p95)** — **over 25x faster**.
3. **Zero Token & Zero VRAM Overhead:**
   - Llama-Guard adds ~235 prompt tokens per interaction and requires 2.5GB GPU VRAM.
   - MCP Sentinel consumes **0 tokens** and runs purely on CPU with negligible footprint.
