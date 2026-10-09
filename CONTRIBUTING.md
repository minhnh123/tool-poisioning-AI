# Contributing to MCP Sentinel

Thank you for your interest in contributing to **MCP Sentinel**! This document provides guidelines for contributing code, reporting security vulnerabilities, and running benchmarks.

---

## 🛠️ Development Setup

1. **Prerequisites**:
   - Python 3.10+ (Python 3.11 or 3.12 recommended)
   - Git

2. **Clone and Setup Virtual Environment**:
   ```bash
   git clone https://github.com/mcp-sentinel/mcp-sentinel.git
   cd mcp-sentinel
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   ```

---

## 🧪 Testing Guidelines

Before submitting a Pull Request, verify that all existing and newly added tests pass:

```bash
# Run full test suite
python -m pytest tests/ -v

# Run evasion tests specifically
python -m pytest tests/test_adversarial_evasion.py -v
```

### Adding New Test Cases
- When adding a new defense detector, add corresponding adversarial samples in `tests/test_adversarial_evasion.py`.
- Ensure test cases are self-contained and run in under 5 seconds.

---

## 📐 Code Style & Architecture Principles

- **PEP 8 Compliance**: Follow standard Python conventions.
- **Dynamic Path Handling**: Never hardcode file paths (use `Path(__file__).resolve().parents[...]`).
- **Structured Logging**: Use `logging.getLogger(__name__)`. Avoid silent exceptions (`except Exception: pass`).
- **Type Annotations**: Add type hints to all public function arguments and return types.

---

## 🔒 Security Vulnerability Reporting

If you discover a potential bypass or security vulnerability within MCP Sentinel, please report it privately via email or repository security advisory rather than public issues.
