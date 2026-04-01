"""MCP Config Generator — creates Model Context Protocol config for Kiro."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


DEFAULT_MCP_SERVERS = {
    "aws-docs": {
        "command": "uvx",
        "args": ["awslabs.aws-documentation-mcp-server@latest"],
        "env": {"FASTMCP_LOG_LEVEL": "ERROR"},
        "disabled": False,
        "autoApprove": [],
    },
}

OPTIONAL_MCP_SERVERS = {
    "postgres": {
        "command": "uvx",
        "args": ["awslabs.postgres-mcp-server@latest"],
        "env": {"FASTMCP_LOG_LEVEL": "ERROR"},
        "disabled": False,
        "autoApprove": [],
    },
    "github": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": ""},
        "disabled": False,
        "autoApprove": [],
    },
    "filesystem": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
        "disabled": False,
        "autoApprove": [],
    },
}


def generate_mcp_config(root: Path, servers: List[str] | None = None) -> Dict:
    """Generate MCP config for Kiro."""
    config = {"mcpServers": {}}

    # Always include aws-docs
    config["mcpServers"].update(DEFAULT_MCP_SERVERS)

    # Add optional servers
    for name in (servers or []):
        if name in OPTIONAL_MCP_SERVERS:
            config["mcpServers"][name] = OPTIONAL_MCP_SERVERS[name]

    return config


def write_mcp_config(root: Path, servers: List[str] | None = None) -> Path:
    """Write MCP config to .kiro/settings/mcp.json."""
    config = generate_mcp_config(root, servers)
    path = root / ".kiro" / "settings" / "mcp.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def list_available_servers() -> List[Dict]:
    """List all available MCP servers."""
    result = []
    for name, cfg in {**DEFAULT_MCP_SERVERS, **OPTIONAL_MCP_SERVERS}.items():
        result.append({
            "name": name,
            "command": cfg["command"],
            "default": name in DEFAULT_MCP_SERVERS,
        })
    return result
