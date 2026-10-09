# Operations Runbook: Incident Response & Tool Quarantine

1. Quarantine Identification: When Sentinel flags a tool with RULE_SQUAT_* or RULE_INJ_*, isolate the MCP server.
2. Audit Verification: Inspect /logs/audit.log and verify affected file paths.
3. Recovery: Restore modified files from backup repository or run update_file to reset configuration.
