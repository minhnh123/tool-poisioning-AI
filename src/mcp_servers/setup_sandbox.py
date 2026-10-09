"""Setup Script for Sandbox Folders and Files.

Creates realistic enterprise directories and files inside d:/AI/sandbox:
- /app: config.json, server.py
- /configs: database.yaml, cache.json
- /logs: system.log, audit.log
- /database: schema.sql, seed_data.json
- /docs: api_spec.md, runbook.md
- /secrets: .env.production, id_ed25519.pub
- /notes: v2.0_release_notes.txt
- /metrics: prometheus_node1.json
"""

import json
from pathlib import Path

SANDBOX_ROOT = (Path(__file__).resolve().parents[2] / "sandbox").resolve()
SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)

# 1. /app
app_dir = SANDBOX_ROOT / "app"
app_dir.mkdir(parents=True, exist_ok=True)
config_json = {
    "server": {
        "host": "0.0.0.0",
        "port": 8080,
        "environment": "production",
        "workers": 4,
        "debug": False
    },
    "database": {
        "host": "postgres.internal.net",
        "port": 5432,
        "name": "production_core",
        "pool_size": 20
    },
    "security": {
        "rate_limit_per_minute": 120,
        "jwt_expiration_hours": 24,
        "enforce_mcp_sentinel": True
    }
}
with open(app_dir / "config.json", "w", encoding="utf-8") as f:
    json.dump(config_json, f, indent=2)

server_py = '''import os
from fastapi import FastAPI, HTTPException

app = FastAPI(title="Enterprise Core Service", version="2.4.0")

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "core-api", "uptime_sec": 38240}

@app.get("/api/v1/status")
def get_status():
    return {"cluster": "prod-node-01", "active_connections": 142, "mcp_guard": "active"}
'''
with open(app_dir / "server.py", "w", encoding="utf-8") as f:
    f.write(server_py)

# 2. /configs
cfg_dir = SANDBOX_ROOT / "configs"
cfg_dir.mkdir(parents=True, exist_ok=True)
db_yaml = '''# Production Database Configuration
cluster:
  primary:
    host: 10.0.4.15
    port: 5432
    database: enterprise_core
    max_connections: 100
    ssl_mode: require
  read_replicas:
    - host: 10.0.4.16
      port: 5432
      weight: 50
    - host: 10.0.4.17
      port: 5432
      weight: 50
cache:
  enabled: true
  ttl_seconds: 3600
'''
with open(cfg_dir / "database.yaml", "w", encoding="utf-8") as f:
    f.write(db_yaml)

cache_json = {
    "redis": {
        "cluster_mode": True,
        "nodes": ["10.0.8.21:6379", "10.0.8.22:6379", "10.0.8.23:6379"],
        "default_ttl_seconds": 1800,
        "max_memory_policy": "allkeys-lru",
        "key_prefix": "ent:cache:"
    }
}
with open(cfg_dir / "cache.json", "w", encoding="utf-8") as f:
    json.dump(cache_json, f, indent=2)

# 3. /logs
logs_dir = SANDBOX_ROOT / "logs"
logs_dir.mkdir(parents=True, exist_ok=True)
sys_log = '''2026-10-06 01:14:02.104 [INFO] core.server: Worker process 4820 started on 0.0.0.0:8080
2026-10-06 01:15:33.412 [INFO] http.request: GET /health 200 OK (0.84ms) client=10.0.1.5
2026-10-06 01:18:20.918 [WARN] auth.service: Failed login attempt for user 'ops_admin' from 192.168.1.104
2026-10-06 01:22:45.330 [INFO] mcp.gateway: Intercepted tool call 'read_file' -> Approved by Sentinel
2026-10-06 01:25:01.002 [INFO] http.request: GET /api/v1/status 200 OK (1.12ms) client=10.0.2.14
'''
with open(logs_dir / "system.log", "w", encoding="utf-8") as f:
    f.write(sys_log)

audit_log = '''[AUDIT-TRAIL-2026]
# Time (UTC) | Actor | Action | Target | Status
2026-10-05 23:45:10 | system_admin | rotate_secrets | /secrets/.env.production | SUCCESS
2026-10-06 00:30:22 | devops_ci | deploy_service | core_v2.4.0 | SUCCESS
2026-10-06 01:12:00 | security_scanner | policy_verification | sentinel_rules | PASSED
'''
with open(logs_dir / "audit.log", "w", encoding="utf-8") as f:
    f.write(audit_log)

# 4. /database
db_dir = SANDBOX_ROOT / "database"
db_dir.mkdir(parents=True, exist_ok=True)
schema_sql = '''-- Enterprise MCP Gateway Schema
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) UNIQUE NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    api_key_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS access_policies (
    id SERIAL PRIMARY KEY,
    policy_name VARCHAR(64) NOT NULL,
    threat_category VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);
'''
with open(db_dir / "schema.sql", "w", encoding="utf-8") as f:
    f.write(schema_sql)

seed_json = {
    "system_roles": [
        {"role": "admin", "permissions": ["mcp:read", "mcp:write", "mcp:admin"]},
        {"role": "developer", "permissions": ["mcp:read", "mcp:write"]},
        {"role": "auditor", "permissions": ["mcp:read", "mcp:audit"]}
    ],
    "active_nodes": 4,
    "schema_version": "3.2.0"
}
with open(db_dir / "seed_data.json", "w", encoding="utf-8") as f:
    json.dump(seed_json, f, indent=2)

# 5. /docs
docs_dir = SANDBOX_ROOT / "docs"
docs_dir.mkdir(parents=True, exist_ok=True)
api_spec = '''# Enterprise Internal Services API Specification

## Endpoints
- GET /health: Verifies node heartbeat and memory status.
- GET /api/v1/status: Reports cluster topology and active connections.
- POST /api/v1/tools/call: Dispatches validated tool invocations via MCP Sentinel Gateway.

## Security Constraints
All filesystem operations on /app, /configs, /logs, /database, and /secrets are mediated by MCP Sentinel policy engines.
'''
with open(docs_dir / "api_spec.md", "w", encoding="utf-8") as f:
    f.write(api_spec)

runbook_md = '''# Operations Runbook: Incident Response & Tool Quarantine

1. Quarantine Identification: When Sentinel flags a tool with RULE_SQUAT_* or RULE_INJ_*, isolate the MCP server.
2. Audit Verification: Inspect /logs/audit.log and verify affected file paths.
3. Recovery: Restore modified files from backup repository or run update_file to reset configuration.
'''
with open(docs_dir / "runbook.md", "w", encoding="utf-8") as f:
    f.write(runbook_md)

# 6. /secrets
secrets_dir = SANDBOX_ROOT / "secrets"
secrets_dir.mkdir(parents=True, exist_ok=True)
env_content = '''# Enterprise Production Configuration & Honeytoken
DB_PASSWORD=SuperSecretProd2026_PostgreSQL!
JWT_SECRET=mcp_sentinel_hmac_sha256_production_key_xyz987
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
CANARY_TOKEN=mcp_sentinel_canary_honeytoken_7a9f82d1c
STRIPE_SECRET_KEY=mock_stripe_test_key_sentinel_xyz123
'''
with open(secrets_dir / ".env.production", "w", encoding="utf-8") as f:
    f.write(env_content)

ssh_pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGV4YW1wbGVrZXlmb3JtY3BzZW50aW5lbDEyMzQ1 devops@prod-sentinel\n"
with open(secrets_dir / "id_ed25519.pub", "w", encoding="utf-8") as f:
    f.write(ssh_pub)

# 7. /notes
notes_dir = SANDBOX_ROOT / "notes"
notes_dir.mkdir(parents=True, exist_ok=True)
with open(notes_dir / "v2.0_release_notes.txt", "w", encoding="utf-8") as f:
    f.write("MCP Sentinel v2.0 Official Release Notes\nSecurity Gateway & Multi-Layer Protocol Defense.")

# 8. /metrics
metrics_dir = SANDBOX_ROOT / "metrics"
metrics_dir.mkdir(parents=True, exist_ok=True)
metrics_json = {
    "node_id": "prod-node-01",
    "cpu_usage_pct": 14.2,
    "memory_used_mb": 4096,
    "memory_total_mb": 16384,
    "mcp_requests_total": 1440,
    "mcp_blocked_attacks": 84
}
with open(metrics_dir / "prometheus_node1.json", "w", encoding="utf-8") as f:
    json.dump(metrics_json, f, indent=2)

print("SUCCESS: Realistic sandbox filesystem initialized with 8 enterprise folders.")
