"""Launcher for MCP Sentinel Web Demo Dashboard.

Run this script to launch the FastAPI server locally:
    python run_dashboard.py
"""

import sys
import uvicorn

if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    
    print("=" * 70)
    print("   STARTING MCP SENTINEL WEB DEMO DASHBOARD")
    print("   URL: http://127.0.0.1:8000")
    print("   Design Standard: Editorial Modern SaaS (DESIGN.md & SKILL.md)")
    print("=" * 70)
    
    uvicorn.run("src.dashboard.app:app", host="127.0.0.1", port=8000, reload=False)
