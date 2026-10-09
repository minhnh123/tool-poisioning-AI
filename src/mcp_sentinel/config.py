"""Configuration for MCP Sentinel Security Gateway.

Defines operating modes, detection thresholds, known standard tool schemas,
and mitigation policies.
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyMode(str, Enum):
    """Mitigation policy enforcement modes."""
    STRICT_BLOCK = "strict_block"  # Completely remove/block malicious tools or requests
    SANITIZE = "sanitize"          # Strip malicious payloads and provide neutralized version
    AUDIT_ONLY = "audit_only"      # Log security findings without altering execution


class SentinelConfig(BaseModel):
    """Central configuration for MCP Sentinel."""
    
    # Mitigation policy
    policy_mode: PolicyMode = Field(
        default=PolicyMode.STRICT_BLOCK,
        description="Policy enforcement mode: strict_block, sanitize, audit_only"
    )
    
    # Static Tool Inspector toggles
    enable_schema_validator: bool = True
    enable_prompt_injection_guard: bool = True
    enable_semantic_detector: bool = True
    enable_squatting_detector: bool = True
    
    # Thresholds
    semantic_similarity_threshold: float = Field(
        default=0.15,
        description="Minimum cosine similarity between tool name and description. Below this is flagged as divergent."
    )
    squatting_similarity_threshold: float = Field(
        default=0.72,
        description="Threshold above which a non-standard tool is flagged as squatting/shadowing a standard tool."
    )
    max_docstring_length: int = Field(
        default=2500,
        description="Maximum permissible length of tool description before raising an anomaly alert."
    )
    
    # Runtime Policy Engine toggles
    enable_honeytoken_tracking: bool = True
    canary_token_prefix: str = "SENTINEL_CANARY_"
    enable_capability_acl: bool = True
    enable_path_traversal_guard: bool = True
    
    # Output Sanitizer toggles
    enable_output_sanitizer: bool = True
    max_output_tokens_scan: int = 4000
    
    # Logging
    log_level: str = "INFO"
    log_security_events: bool = True


# Standard legitimate tool baselines for Tool Squatting / Shadowing detection
STANDARD_TOOL_REGISTRY: Dict[str, Dict[str, str]] = {
    "read_file": {
        "domain": "filesystem",
        "description": "Read the complete contents of a file from the local filesystem with UTF-8 encoding.",
        "allowed_params": ["path", "encoding"]
    },
    "write_file": {
        "domain": "filesystem",
        "description": "Write or overwrite contents into a specified file on the local filesystem.",
        "allowed_params": ["path", "content", "encoding"]
    },
    "list_directory": {
        "domain": "filesystem",
        "description": "List files, subdirectories, and metadata in a given directory path.",
        "allowed_params": ["path", "recursive", "show_hidden"]
    },
    "fetch_web_content": {
        "domain": "network",
        "description": "Fetches raw HTML or text content from a specified URL using standard HTTP GET.",
        "allowed_params": ["url", "headers", "timeout"]
    },
    "web_search": {
        "domain": "network",
        "description": "Searches the web for relevant search results and abstracts.",
        "allowed_params": ["query", "limit"]
    },
    "execute_query": {
        "domain": "database",
        "description": "Executes a read-only or transactional SQL query against the configured database.",
        "allowed_params": ["query", "database", "params"]
    },
    "bash": {
        "domain": "devops",
        "description": "Executes shell commands in a sandboxed bash terminal.",
        "allowed_params": ["command", "timeout"]
    }
}
