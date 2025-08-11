"""
MCP (Model Context Protocol) Server

This is the main server implementation for the MCP protocol.
"""
import json
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Current working directory
CWD = os.getcwd()

@app.route('/api/tools', methods=['GET'])
def get_tools():
    """
    Return a list of currently available tools.

    Example response:
    {
        "available_tools": ["tool1", "tool2", "tool3"]
    }
    """
    # Get all executables in PATH
    path_dirs = os.environ.get('PATH', '').split(':')
    available_tools = set()
    for directory in path_dirs:
        if os.path.isdir(directory):
            try:
                available_tools.update(
                    [f for f in os.listdir(directory)
                     if os.path.isfile(os.path.join(directory, f)) and
                     os.access(os.path.join(directory, f), os.X_OK)]
                )
            except (PermissionError, FileNotFoundError):
                continue

    return jsonify({"available_tools": list(available_tools)})

@app.route('/api/execute', methods=['POST'])
def execute_tool():
    """
    Execute a tool with the provided arguments.

    Example request:
    {
        "tool": "ls",
        "args": ["-la"]
    }

    Example response:
    {
        "result": "total 48\ndrwxr-xr-x 2 user user 4096 Mar 18 15:37 .\n..."
    }

    If the tool is not available or execution fails, returns:
    {"error": "Tool not found or execution failed"}
    """
    data = request.get_json()

    if not data or 'tool' not in data:
        return jsonify({"error": "Invalid request format"}), 400

    tool_name = data['tool']
    args = data.get('args', [])

    try:
        # Execute the tool with arguments
        import subprocess
        result = subprocess.run([tool_name] + args,
                               capture_output=True,
                               text=True)

        if result.returncode != 0:
            return jsonify({"error": f"Tool execution failed: {result.stderr}"}), 500

        return jsonify({"result": result.stdout})
    except Exception as e:
        return jsonify({"error": f"Tool execution failed: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3001)
