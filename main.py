#!/usr/bin/env python3
import os
import subprocess
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Build the list of all Kali tools from common bin dirs
KALI_TOOL_DIRS = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"]
all_kali_tools = []
for d in KALI_TOOL_DIRS:
    if os.path.exists(d):
        all_kali_tools.extend(os.listdir(d))
all_kali_tools = sorted(set(all_kali_tools))

# FastAPI app
app = FastAPI(title="Kali Tools API", version="1.0.0")


# Request/Response models
class ToolExecuteRequest(BaseModel):
    tool: str
    arguments: List[str] = []
    timeout: int = 60


class ToolExecuteResponse(BaseModel):
    stdout: str
    stderr: str
    return_code: int


class ToolInfo(BaseModel):
    name: str
    available: bool


# Endpoints
@app.get("/")
async def root():
    return {
        "message": "Kali Tools API Server",
        "total_tools": len(all_kali_tools),
        "endpoints": {
            "/tools": "List all available tools",
            "/tools/{tool_name}": "Check if a specific tool exists",
            "/execute": "Execute a tool with arguments",
        },
    }


@app.get("/tools", response_model=List[str])
async def list_tools(limit: Optional[int] = None):
    """List all available Kali tools"""
    if limit:
        return all_kali_tools[:limit]
    return all_kali_tools


@app.get("/tools/{tool_name}", response_model=ToolInfo)
async def check_tool(tool_name: str):
    """Check if a specific tool is available"""
    return ToolInfo(name=tool_name, available=tool_name in all_kali_tools)


@app.post("/execute", response_model=ToolExecuteResponse)
async def execute_tool(request: ToolExecuteRequest):
    """Execute a Kali tool with specified arguments"""

    # Validate tool exists
    if request.tool not in all_kali_tools:
        raise HTTPException(status_code=404, detail=f"Tool '{request.tool}' not found")

    # Security warning: This is potentially dangerous!
    # Consider adding authentication and input validation

    try:
        result = subprocess.run(
            [request.tool] + request.arguments,
            capture_output=True,
            text=True,
            timeout=request.timeout,
        )

        return ToolExecuteResponse(
            stdout=result.stdout, stderr=result.stderr, return_code=result.returncode
        )

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408, detail=f"Command timed out after {request.timeout} seconds"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error executing tool: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "tools_loaded": len(all_kali_tools) > 0}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=3001)
