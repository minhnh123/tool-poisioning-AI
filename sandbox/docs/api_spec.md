# Enterprise Internal Services API Specification

## Endpoints
- GET /health: Verifies node heartbeat and memory status.
- GET /api/v1/status: Reports cluster topology and active connections.
- POST /api/v1/tools/call: Dispatches validated tool invocations via MCP Sentinel Gateway.

## Security Constraints
All filesystem operations on /app, /configs, /logs, /database, and /secrets are mediated by MCP Sentinel policy engines.
