import asyncio
import json
import subprocess
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import logging

app = FastAPI(title="Kali MCP Server", version="1.0.0")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === Models ===

class CommandRequest(BaseModel):
    command: str
    timeout: int = 30

class CommandResponse(BaseModel):
    output: str
    error: Optional[str]
    returncode: int

class ToolInfo(BaseModel):
    name: str
    description: str
    usage: str

# === Tool Metadata ===

TOOLS = {
    "echo": ToolInfo(
        name="echo",
        description="Echoes a message",
        usage="echo <message>"
    ),
    "nmap": ToolInfo(
        name="nmap",
        description="Network discovery and security auditing tool",
        usage="nmap [options] <target>"
    ),
    # (Add your other tools here...)
}

# === Routes ===

@app.get("/")
async def root():
    return {
        "message": "Kali Linux MCP Server",
        "version": "1.0.0",
        "tools_available": list(TOOLS.keys()),
    }

@app.get("/tools")
async def get_tools():
    return {"available_tools": TOOLS}

@app.get("/tools/{tool_name}")
async def get_tool_info(tool_name: str):
    if tool_name not in TOOLS:
        raise HTTPException(status_code=404, detail="Tool not found")
    return TOOLS[tool_name]

@app.post("/execute")
async def execute_command(request: CommandRequest):
    return await run_command(request.command, timeout=request.timeout)

@app.post("/execute_batch")
async def execute_batch_commands(commands: List[CommandRequest]):
    results = []
    for cmd_req in commands:
        results.append(await run_command(cmd_req.command, timeout=cmd_req.timeout))
    return {"results": results}

# === MCP-Compatible Endpoint for LM Studio ===

@app.post("/call-tool")
async def call_tool(request: Request):
    """
    Expected input:
    {
        "tool": "nmap",
        "input": { "command": "nmap -v scanme.nmap.org" }
    }
    """
    body = await request.json()
    tool = body.get("tool")
    input_data = body.get("input", {})
    command = input_data.get("command")

    if not tool or not command:
        raise HTTPException(status_code=400, detail="Missing 'tool' or 'input.command'")

    # Validate allowed tool
    if tool not in TOOLS:
        raise HTTPException(status_code=404, detail="Tool not found")

    # SSE stream
    async def event_stream():
        result = await run_command(command)
        json_data = json.dumps(result)
        yield f"data: {json_data}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")

# === Command Runner ===

async def run_command(command: str, timeout: int = 30) -> Dict[str, Any]:
    try:
        logger.info(f"Executing: {command}")
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return {
            "output": result.stdout,
            "error": result.stderr if result.stderr else None,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "output": "",
            "error": f"Command timed out after {timeout} seconds",
            "returncode": -1,
        }
    except Exception as e:
        return {"output": "", "error": str(e), "returncode": -1}

# === Optional for dev run ===
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)