#!/usr/bin/env python3
"""
Kali MCP Server - Model Context Protocol server for Kali Linux tools.

This server exposes Kali Linux security testing tools through MCP,
allowing LLMs to discover and execute tools like nmap, sqlmap, hydra, etc.

Usage:
    python3 server.py [--transport stdio|streamable-http]
"""

import asyncio
import os
import subprocess
from typing import List, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Create MCP server instance
mcp = FastMCP(
    name="kali-tools",
    instructions="Kali Linux security testing tools server for AI agents. Provides access to discover and execute Kali Linux tools like nmap, sqlmap, hydra, metasploit, etc."
)

# Build the list of all Kali tools from common bin dirs
KALI_TOOL_DIRS = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"]
all_kali_tools: set[str] = set()

for d in KALI_TOOL_DIRS:
    if os.path.exists(d):
        try:
            all_kali_tools.update(os.listdir(d))
        except Exception:
            pass

# Sort tools for consistent ordering
sorted_tools = sorted(all_kali_tools)


class ToolInfo(BaseModel):
    """Tool information model."""
    name: str = Field(description="Name of the Kali tool")
    available: bool = Field(description="Whether the tool is installed")


class ExecuteResult(BaseModel):
    """Execution result model."""
    stdout: str = Field(description="Standard output from command")
    stderr: str = Field(description="Standard error from command")
    return_code: int = Field(description="Exit code of the command")


@mcp.tool()
def list_tools(limit: Optional[int] = None) -> List[str]:
    """List all available Kali tools.
    
    Args:
        limit: Optional maximum number of tools to return. If not provided,
               returns all available tools.
    
    Returns:
        List of tool names available in the Kali system
    """
    if limit:
        return sorted_tools[:limit]
    return sorted_tools


@mcp.tool()
def check_tool(tool_name: str) -> ToolInfo:
    """Check if a specific Kali tool is available.
    
    Args:
        tool_name: Name of the tool to check
    
    Returns:
        ToolInfo with name and availability status
    """
    return ToolInfo(
        name=tool_name,
        available=tool_name in all_kali_tools
    )


@mcp.tool()
def execute_tool(
    tool: str,
    arguments: List[str] = [],
    timeout: int = 60
) -> ExecuteResult:
    """Execute a Kali tool with specified arguments.
    
    ⚠️  WARNING: This allows execution of system commands. Use with caution.
    
    Args:
        tool: Name of the Kali tool to execute
        arguments: List of command line arguments for the tool
        timeout: Timeout in seconds for command execution (default: 60)
    
    Returns:
        ExecuteResult with stdout, stderr, and return code
    
    Raises:
        ValueError: If the tool is not found
        subprocess.TimeoutExpired: If command execution times out
    """
    # Validate tool exists
    if tool not in all_kali_tools:
        raise ValueError(f"Tool '{tool}' not found. Available tools: {len(sorted_tools)}")
    
    try:
        result = subprocess.run(
            [tool] + arguments,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        return ExecuteResult(
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode
        )
    
    except subprocess.TimeoutExpired:
        raise ValueError(f"Command timed out after {timeout} seconds")
    
    except Exception as e:
        raise ValueError(f"Error executing tool: {str(e)}")


@mcp.tool()
def health_check() -> dict:
    """Check server health status.
    
    Returns:
        Dictionary with health status and tools count
    """
    return {
        "status": "healthy",
        "tools_loaded": len(all_kali_tools)
    }


@mcp.tool()
def server_info() -> dict:
    """Get server information and available endpoints.
    
    Returns:
        Dictionary with server metadata and endpoint descriptions
    """
    return {
        "server_name": mcp.name,
        "instructions": mcp.instructions,
        "tools_count": len(sorted_tools),
        "endpoints": [
            {"name": "list_tools", "description": "List all available Kali tools"},
            {"name": "check_tool", "description": "Check if a specific tool exists"},
            {"name": "execute_tool", "description": "Execute a Kali tool with arguments"},
            {"name": "health_check", "description": "Check server health status"},
        ],
    }


# Add tools resource for dynamic discovery
@mcp.resource("kali://tools/available")
def get_available_tools() -> str:
    """Get list of all available Kali tools as a resource."""
    return "\n".join(sorted_tools)


@mcp.resource("kali://tools/count")
def get_tools_count() -> str:
    """Get count of available Kali tools."""
    return f"Total tools: {len(sorted_tools)}"


if __name__ == "__main__":
    import uvicorn
    import sys
    
    # Check transport mode from environment
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    
    # Check for transport argument in command line
    if len(sys.argv) > 1 and sys.argv[1] == "--transport":
        if len(sys.argv) > 2:
            transport = sys.argv[2]
    
    if transport == "streamable-http":
        # Run as HTTP server
        port = int(os.environ.get("MCP_PORT", 3001))
        print(f"Starting Kali MCP Server on port {port}", file=sys.stderr)
        uvicorn.run(mcp._app, host="0.0.0.0", port=port)
    else:
        # Run with stdio transport (default for MCP)
        print("Starting Kali MCP Server with stdio transport", file=sys.stderr)
mcp.run(transport="stdio")
    # Remove duplicate code that was causing syntax errors
