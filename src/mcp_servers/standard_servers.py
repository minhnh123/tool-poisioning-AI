"""
Standard MCP Servers Testbed
Cung cấp các công cụ chuẩn (Benign Tools) cho 3 dịch vụ phổ biến:
1. Filesystem Server
2. Web Fetch Server
3. SQLite Database Server
"""

import os
import sqlite3
import urllib.request
from typing import Dict, Any, List

# ==========================================
# 1. FILESYSTEM TOOLS DEFINITIONS
# ==========================================
FILESYSTEM_TOOLS = [
    {
        "name": "read_file",
        "description": "Read the complete contents of a file from the local filesystem with UTF-8 encoding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative or absolute path to the file"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "write_file",
        "description": "Write text content to a specified file on the local filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Destination file path"},
                "content": {"type": "string", "description": "Text content to write"}
            },
            "required": ["path", "content"]
        }
    },
    {
        "name": "list_directory",
        "description": "List all files and subdirectories within a given folder path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Folder path to list", "default": "."}
            },
            "required": ["path"]
        }
    }
]

# ==========================================
# 2. WEB FETCH TOOLS DEFINITIONS
# ==========================================
FETCH_TOOLS = [
    {
        "name": "fetch_url",
        "description": "Fetch the HTML or raw text content of a specified web URL via HTTP GET.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to retrieve (http/https)"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "search_web",
        "description": "Perform a web search for relevant documentation, articles, or news snippets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query keywords"}
            },
            "required": ["query"]
        }
    }
]

# ==========================================
# 3. SQLITE DATABASE TOOLS DEFINITIONS
# ==========================================
SQLITE_TOOLS = [
    {
        "name": "execute_query",
        "description": "Execute a safe SELECT SQL query against the local SQLite database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "SQL query to execute"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "list_tables",
        "description": "Retrieve the list of all available tables in the current SQLite database.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
]

def get_all_standard_tools() -> List[Dict[str, Any]]:
    """Trả về danh sách toàn bộ các standard benign tools."""
    return FILESYSTEM_TOOLS + FETCH_TOOLS + SQLITE_TOOLS

def execute_mock_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Giả lập thực thi tool an toàn trong môi trường testbed."""
    if tool_name == "read_file":
        return {"status": "success", "content": f"[Simulated content of {arguments.get('path', 'unknown')}]"}
    elif tool_name == "write_file":
        return {"status": "success", "message": f"Wrote {len(arguments.get('content', ''))} chars to {arguments.get('path')}"}
    elif tool_name == "list_directory":
        return {"status": "success", "files": ["config.json", "data.sqlite", "notes.txt"]}
    elif tool_name == "fetch_url":
        return {"status": "success", "content": f"Mock webpage content for {arguments.get('url')}"}
    elif tool_name == "search_web":
        return {"status": "success", "results": [f"Result 1 for {arguments.get('query')}"]}
    elif tool_name == "list_tables":
        return {"status": "success", "tables": ["users", "transactions", "system_logs"]}
    elif tool_name == "execute_query":
        return {"status": "success", "rows": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}
    return {"status": "error", "message": f"Unknown tool: {tool_name}"}
