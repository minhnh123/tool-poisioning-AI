"""Transparent JSON-RPC Stdio Proxy Gateway for MCP Sentinel.

Acts as a security reverse-proxy between an MCP Client (e.g., Claude Desktop,
Cursor, or Python Agent) and an MCP Server.
"""

import sys
import json
import subprocess
import argparse
import threading
from typing import Optional
from .config import SentinelConfig, PolicyMode
from .gateway import MCPSentinelGateway

# Reconfigure stdout/stdin for clean UTF-8 handling
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stdin, "reconfigure"):
    sys.stdin.reconfigure(encoding="utf-8")


class MCPStdioProxy:
    """Transparent stdio JSON-RPC proxy with real-time MCP Sentinel protection."""

    def __init__(self, server_cmd: str, config: Optional[SentinelConfig] = None):
        self.server_cmd = server_cmd
        self.config = config or SentinelConfig()
        self.gateway = MCPSentinelGateway(self.config)
        self.process: Optional[subprocess.Popen] = None

    def start(self):
        """Starts downstream MCP server subprocess and attaches stdio streams."""
        # Launch downstream MCP server process
        self.process = subprocess.Popen(
            self.server_cmd,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            encoding="utf-8"
        )

        # Thread to read responses from downstream server and relay to client stdout
        server_to_client_thread = threading.Thread(target=self._relay_server_to_client, daemon=True)
        server_to_client_thread.start()

        # Main thread reads requests from client stdin and relays to server
        self._relay_client_to_server()

    def _relay_client_to_server(self):
        """Client -> Sentinel Gateway -> Downstream Server."""
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue

                try:
                    rpc_req = json.loads(line)
                except Exception:
                    # Non-JSON line, forward as-is
                    self._send_to_server(line)
                    continue

                method = rpc_req.get("method")
                req_id = rpc_req.get("id")

                # Intercept tools/call request
                if method == "tools/call":
                    params = rpc_req.get("params", {})
                    tool_name = params.get("name", "")
                    arguments = params.get("arguments", {})

                    validation = self.gateway.intercept_tools_call(tool_name, arguments)
                    if not validation.allowed:
                        # Return JSON-RPC error directly to client
                        err_resp = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {
                                "code": -32000,
                                "message": f"[MCP SENTINEL BLOCKED]: {validation.execution_blocked_reason}",
                                "data": [f.model_dump() for f in validation.findings]
                            }
                        }
                        self._send_to_client(json.dumps(err_resp))
                        continue

                    # If sanitized, update arguments
                    if validation.sanitized_arguments and self.config.policy_mode == PolicyMode.SANITIZE:
                        params["arguments"] = validation.sanitized_arguments
                        rpc_req["params"] = params
                        line = json.dumps(rpc_req)

                self._send_to_server(line)
        except (KeyboardInterrupt, BrokenPipeError):
            pass

    def _relay_server_to_client(self):
        """Downstream Server -> Sentinel Gateway -> Client."""
        try:
            if not self.process or not self.process.stdout:
                return

            for line in self.process.stdout:
                line = line.strip()
                if not line:
                    continue

                try:
                    rpc_resp = json.loads(line)
                except Exception:
                    self._send_to_client(line)
                    continue

                result = rpc_resp.get("result")

                # Intercept tools/list response
                if isinstance(result, dict) and "tools" in result:
                    raw_tools = result.get("tools", [])
                    filtered_tools, _ = self.gateway.intercept_tools_list(raw_tools)
                    result["tools"] = filtered_tools
                    rpc_resp["result"] = result
                    line = json.dumps(rpc_resp)

                # Intercept tools/call response
                elif isinstance(result, dict) and ("content" in result or "data" in result or "raw_content" in result):
                    sanitization = self.gateway.intercept_tools_response("tool_call", result)
                    if sanitization.sanitized_output:
                        rpc_resp["result"] = sanitization.sanitized_output
                        line = json.dumps(rpc_resp)

                self._send_to_client(line)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_to_server(self, data: str):
        if self.process and self.process.stdin:
            self.process.stdin.write(data + "\n")
            self.process.stdin.flush()

    def _send_to_client(self, data: str):
        sys.stdout.write(data + "\n")
        sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description="MCP Sentinel Transparent Stdio Proxy Gateway")
    parser.add_argument("--server-cmd", required=True, help="Command to launch downstream MCP server")
    parser.add_argument("--mode", default="strict_block", choices=["strict_block", "sanitize", "audit_only"],
                        help="Security policy enforcement mode")
    args = parser.parse_args()

    config = SentinelConfig(policy_mode=PolicyMode(args.mode))
    proxy = MCPStdioProxy(server_cmd=args.server_cmd, config=config)
    proxy.start()


if __name__ == "__main__":
    main()
