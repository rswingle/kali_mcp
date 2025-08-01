import asyncio
import json
import subprocess
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello from Kali Docker"}

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Kali MCP Server", version="1.0.0")


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


# Define available tools and their descriptions
TOOLS = {
    "nmap": ToolInfo(
        name="nmap",
        description="Network discovery and security auditing tool",
        usage="nmap [options] <target>",
    ),
    "sqlmap": ToolInfo(
        name="sqlmap",
        description="Automatic SQL injection and database takeover tool",
        usage="sqlmap [options] --url=<target>",
    ),
    "metasploit": ToolInfo(
        name="msfconsole",
        description="Metasploit Framework console for penetration testing",
        usage="msfconsole -q -x 'use exploit/multi/handlers; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST <ip>; set LPORT <port>; exploit'",
    ),
    "hydra": ToolInfo(
        name="hydra",
        description="Network login cracker supporting multiple protocols",
        usage="hydra [options] <target> <service>",
    ),
    "nikto": ToolInfo(
        name="nikto",
        description="Web server scanner for vulnerabilities",
        usage="nikto -h <target>",
    ),
    "gobuster": ToolInfo(
        name="gobuster",
        description="Directory/file brute-forcer",
        usage="gobuster dir -u <url> -w /usr/share/seclists/Discovery/Web-Content/common.txt",
    ),
    "enum4linux": ToolInfo(
        name="enum4linux",
        description="Enumerates information from Windows and Samba systems",
        usage="enum4linux <target>",
    ),
    "dirb": ToolInfo(
        name="dirb",
        description="Web directory brute-forcer",
        usage="dirb <url> [wordlist]",
    ),
    "wpscan": ToolInfo(
        name="wpscan",
        description="WordPress security scanner",
        usage="wpscan --url <target>",
    ),
    "whatweb": ToolInfo(
        name="whatweb", description="Website fingerprinter", usage="whatweb <target>"
    ),
    "dnsrecon": ToolInfo(
        name="dnsrecon",
        description="DNS enumeration tool",
        usage="dnsrecon -d <domain>",
    ),
    "sublist3r": ToolInfo(
        name="sublist3r",
        description="Fast subdomain enumeration tool",
        usage="sublist3r -d <domain>",
    ),
    "amass": ToolInfo(
        name="amass",
        description="Attack surface mapping and asset discovery",
        usage="amass enum -d <domain>",
    ),
    "theharvester": ToolInfo(
        name="theharvester",
        description="Reconnaissance tool for email and subdomain harvesting",
        usage="theharvester -d <domain> -l 50 -b all",
    ),
    "nbtscan": ToolInfo(
        name="nbtscan",
        description="NBT scanner for Windows hosts and SMB shares",
        usage="nbtscan <target>",
    ),
    "onesixtyone": ToolInfo(
        name="onesixtyone",
        description="SNMP scanner for discovering devices and community strings",
        usage="onesixtyone <target>",
    ),
    "sslscan": ToolInfo(
        name="sslscan",
        description="SSL/TLS client and server scanner",
        usage="sslscan <target>",
    ),
    "seclists": ToolInfo(
        name="seclists",
        description="Collection of various wordlists for security testing",
        usage="using already installed wordlists in /usr/share/seclists",
    ),
}


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
    try:
        logger.info(f"Executing command: {request.command}")

        # Limit dangerous commands for safety
        dangerous_commands = ["rm", "mv", "cp", "chmod", "chown"]
        for cmd in dangerous_commands:
            if cmd in request.command.lower():
                raise HTTPException(
                    status_code=400,
                    detail=f"Command '{cmd}' is[48;108;143;1728;1144t not allowed",
                )

        # Execute the command
        result = subprocess.run(
            request.command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=request.timeout,
        )

        logger.info(
            f"Command executed successfully with return code: {result.returncode}"
        )

        response = CommandResponse(
            output=result.stdout,
            error=result.stderr if result.stderr else None,
            returncode=result.returncode,
        )

        return response

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Command execution timed out")
    except subprocess.SubprocessError as e:
        raise HTTPException(status_code=500, detail=f"Subprocess error: {str(e)}")
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error executing command: {str(e)}"
        )


@app.post("/execute_batch")
async def execute_batch_commands(commands: List[CommandRequest]):
    results = []

    for cmd_req in commands:
        try:
            logger.info(f"Executing batch command: {cmd_req.command}")

            # Limit dangerous commands
            dangerous_commands = ["rm", "mv", "cp", "chmod", "chown"]
            for cmd in dangerous_commands:
                if cmd in cmd_req.command.lower():
                    results.append(
                        {
                            "command": cmd_req.command,
                            "output": "",
                            "error": f"Command '{cmd}' is not allowed",
                            "returncode": 1,
                        }
                    )
                    continue

            result = subprocess.run(
                cmd_req.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=cmd_req.timeout,
            )

            results.append(
                {
                    "command": cmd_req.command,
                    "output": result.stdout,
                    "error": result.stderr if result.stderr else None,
                    "returncode": result.returncode,
                }
            )

        except Exception as e:
            results.append(
                {
                    "command": cmd_req.command,
                    "output": "",
                    "error": str(e),
                    "returncode": -1,
                }
            )

    return {"results": results}


async def run_command(command: str, timeout: int = 30) -> Dict[str, Any]:
    """Helper function to run commands with error handling"""
    try:
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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=3000)
