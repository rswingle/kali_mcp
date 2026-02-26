#!/usr/bin/env python3

# Test script to verify MCP server startup and basic functionality
import subprocess
import sys
import time

def test_mcp_server():
    """Test that the MCP server starts correctly"""
    
    # Test running the server with stdio transport
    try:
        # Run a quick test to see if the server can start with stdio
        # Run a quick test to see if the server can start with stdio
        result = subprocess.run([
            "docker", "run", "--rm", "-i", 
            "kali-mcp-server:latest",
            "--transport", "stdio"
        ], 
        input=b'{"jsonrpc": "2.0", "method": "mcp.server.listTools", "id": 1}\n',
        capture_output=True, 
        text=True, 
        timeout=10)
            "docker", "run", "--rm", "-i", 
            "kali-mcp-server:latest",
            "--transport", "stdio"
        ], 
        input=b'{"jsonrpc": "2.0", "method": "mcp.server.listTools", "id": 1}\n',
        capture_output=True, 
        text=True, 
        timeout=10)
        
        print("Return code:", result.returncode)
        print("STDOUT:", repr(result.stdout))
        print("STDERR:", repr(result.stderr))
        
        # If we get here without timeout, the server started correctly
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("Server timed out - likely connection issue")
        return False
    except Exception as e:
        print(f"Error running server test: {e}")
        return False

if __name__ == "__main__":
    success = test_mcp_server()
    sys.exit(0 if success else 1)