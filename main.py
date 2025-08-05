import asyncio
import json
import subprocess
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging
import os

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

# Define commonly used security tools from the tools.list file
TOOLS = {
    "nmap": ToolInfo(
        name="nmap",
        description="Network discovery and security auditing tool",
        usage="nmap [options] <target>"
    ),
    "sqlmap": ToolInfo(
        name="sqlmap",
        description="Automatic SQL injection and database takeover tool",
        usage="sqlmap [options] --url=<target>"
    ),
    "metasploit": ToolInfo(
        name="msfconsole",
        description="Metasploit Framework console for penetration testing",
        usage="msfconsole -q -x 'use exploit/multi/handlers; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST <ip>; set LPORT <port>; exploit'"
    ),
    "hydra": ToolInfo(
        name="hydra",
        description="Network login cracker supporting multiple protocols",
        usage="hydra [options] <target> <service>"
    ),
    "nikto": ToolInfo(
        name="nikto",
        description="Web server scanner for vulnerabilities",
        usage="nikto -h <target>"
    ),
    "gobuster": ToolInfo(
        name="gobuster",
        description="Directory/file brute-forcer",
        usage="gobuster dir -u <url> -w /usr/share/seclists/Discovery/Web-Content/common.txt"
    ),
    "enum4linux": ToolInfo(
        name="enum4linux",
        description="Enumerates information from Windows and Samba systems",
        usage="enum4linux <target>"
    ),
    "dirb": ToolInfo(
        name="dirb",
        description="Web directory brute-forcer",
        usage="dirb <url> [wordlist]"
    ),
    "wpscan": ToolInfo(
        name="wpscan",
        description="WordPress security scanner",
        usage="wpscan --url <target>"
    ),
    "whatweb": ToolInfo(
        name="whatweb",
        description="Website fingerprinter",
        usage="whatweb <target>"
    ),
    "dnsrecon": ToolInfo(
        name="dnsrecon",
        description="DNS enumeration tool",
        usage="dnsrecon -d <domain>"
    ),
    "sublist3r": ToolInfo(
        name="sublist3r",
        description="Fast subdomain enumeration tool",
        usage="sublist3r -d <domain>"
    ),
    "amass": ToolInfo(
        name="amass",
        description="Attack surface mapping and asset discovery",
        usage="amass enum -d <domain>"
    ),
    "theharvester": ToolInfo(
        name="theharvester",
        description="Reconnaissance tool for email and subdomain harvesting",
        usage="theharvester -d <domain> -l 50 -b all"
    ),
    "nbtscan": ToolInfo(
        name="nbtscan",
        description="NBT scanner for Windows hosts and SMB shares",
        usage="nbtscan <target>"
    ),
    "onesixtyone": ToolInfo(
        name="onesixtyone",
        description="SNMP scanner for discovering devices and community strings",
        usage="onesixtyone <target>"
    ),
    "sslscan": ToolInfo(
        name="sslscan",
        description="SSL/TLS client and server scanner",
        usage="sslscan <target>"
    ),
    "seclists": ToolInfo(
        name="seclists",
        description="Collection of various wordlists for security testing",
        usage="using already installed wordlists in /usr/share/seclists"
    ),
    "aircrack-ng": ToolInfo(
        name="aircrack-ng",
        description="WiFi security auditing tool",
        usage="aircrack-ng <capture_file>"
    ),
    "airgeddon": ToolInfo(
        name="airgeddon",
        description="WiFi security auditing and penetration testing tool",
        usage="airgeddon"
    ),
    "bettercap": ToolInfo(
        name="bettercap",
        description="Man-in-the-middle attack framework",
        usage="bettercap -iface <interface> -eval 'set http.proxy.response.headers.X-Forwarded-For 127.0.0.1'"
    ),
    "burpsuite": ToolInfo(
        name="burpsuite",
        description="Web application security testing platform",
        usage="burpsuite"
    ),
    "cme": ToolInfo(
        name="crackmapexec",
        description="Post-exploitation tool for Windows environments",
        usage="crackmapexec <target> -u <username> -p <password>"
    ),
    "empire": ToolInfo(
        name="empire",
        description="Post-exploitation framework",
        usage="empire"
    ),
    "ettercap": ToolInfo(
        name="ettercap",
        description="Man-in-the-middle attack tool",
        usage="ettercap -G"
    ),
    "fierce": ToolInfo(
        name="fierce",
        description="DNS reconnaissance tool",
        usage="fierce -dns <domain>"
    ),
    "ffuf": ToolInfo(
        name="ffuf",
        description="Fast web fuzzer",
        usage="ffuf -u http://<target>/FUZZ -w /usr/share/wordlists/dirb/common.txt"
    ),
    "hashcat": ToolInfo(
        name="hashcat",
        description="Advanced password recovery tool",
        usage="hashcat -m <mode> <hash_file> <wordlist>"
    ),
    "joomscan": ToolInfo(
        name="joomscan",
        description=" Joomla vulnerability scanner",
        usage="joomscan -u <target>"
    ),
    "john": ToolInfo(
        name="john",
        description="Password cracker",
        usage="john <hash_file>"
    ),
    "maltego": ToolInfo(
        name="maltego",
        description="Link analysis and data mining tool",
        usage="maltego"
    ),
    "nuclei": ToolInfo(
        name="nuclei",
        description="Fast and customizable vulnerability scanner",
        usage="nuclei -u <target> -t /usr/share/nuclei-templates/"
    ),
    "openvas": ToolInfo(
        name="openvas",
        description="OpenVAS vulnerability scanner",
        usage="openvas-start"
    ),
    "radare2": ToolInfo(
        name="radare2",
        description="Reverse engineering framework",
        usage="r2 <binary_file>"
    ),
    "responder": ToolInfo(
        name="responder",
        description="LLMNR, NBT-NS and MDNS poisoner",
        usage="responder -I <interface>"
    ),
    "sslstrip": ToolInfo(
        name="sslstrip",
        description="HTTPS stripping tool",
        usage="sslstrip -l <port>"
    ),
    "uniscan": ToolInfo(
        name="uniscan",
        description="Web vulnerability scanner",
        usage="uniscan -u <target>"
    ),
    "wafw00f": ToolInfo(
        name="wafw00f",
        description="Web Application Firewall detection tool",
        usage="wafw00f <target>"
    ),
    "yersinia": ToolInfo(
        name="yersinia",
        description="Network protocol attack tool",
        usage="yersinia -G"
    ),
    "zaproxy": ToolInfo(
        name="zap",
        description="Web application security scanner",
        usage="zap.sh"
    ),
    "zmap": ToolInfo(
        name="zmap",
        description="Fast network scanner",
        usage="zmap -p <port> <target>"
    ),
    "dnsenum": ToolInfo(
        name="dnsenum",
        description="DNS enumeration tool",
        usage="dnsenum <domain>"
    ),
    "dnsscan": ToolInfo(
        name="dnsscan",
        description="DNS scanning tool",
        usage="dnsscan <domain>"
    ),
    "dnsx": ToolInfo(
        name="dnsx",
        description="DNS resolution tool",
        usage="dnsx -d <domain>"
    ),
    "recon-ng": ToolInfo(
        name="recon-ng",
        description="Web reconnaissance framework",
        usage="recon-ng"
    ),
    "sqlninja": ToolInfo(
        name="sqlninja",
        description="SQL injection tool",
        usage="sqlninja -u <url>"
    ),
    "xsser": ToolInfo(
        name="xsser",
        description="XSS vulnerability scanner",
        usage="xsser -u <url>"
    ),
    "zap-cli": ToolInfo(
        name="zap-cli",
        description="Command line interface for OWASP ZAP",
        usage="zap-cli quick-scan --self-contained <target>"
    ),
    "medusa": ToolInfo(
        name="medusa",
        description="Network login cracker",
        usage="medusa -H <target> -u <username> -p <password>"
    ),
    "smbclient": ToolInfo(
        name="smbclient",
        description="SMB/CIFS client for accessing SMB/CIFS shares",
        usage="smbclient -L <target>"
    ),
    "smbmap": ToolInfo(
        name="smbmap",
        description="SMB enumeration tool",
        usage="smbmap -H <target>"
    ),
    "rpcclient": ToolInfo(
        name="rpcclient",
        description="RPC client for Windows systems",
        usage="rpcclient -U <username> <target>"
    ),
    "smbget": ToolInfo(
        name="smbget",
        description="SMB file download tool",
        usage="smbget -R -u <username> -p <password> -s <target>"
    ),
    "smbpasswd": ToolInfo(
        name="smbpasswd",
        description="Samba password management tool",
        usage="smbpasswd -a <username>"
    ),
    "mssqlclient": ToolInfo(
        name="mssqlclient",
        description="MSSQL client tool",
        usage="mssqlclient <username>@<target>"
    ),
    "mysql": ToolInfo(
        name="mysql",
        description="MySQL client tool",
        usage="mysql -h <target> -u <username> -p"
    ),
    "postgresql": ToolInfo(
        name="postgresql",
        description="PostgreSQL client tool",
        usage="psql -h <target> -U <username>"
    ),
    "ldapsearch": ToolInfo(
        name="ldapsearch",
        description="LDAP search tool",
        usage="ldapsearch -x -H ldap://<target> -b <base_dn>"
    ),
    "snmpwalk": ToolInfo(
        name="snmpwalk",
        description="SNMP walk tool",
        usage="snmpwalk -v 2c -c public <target>"
    ),
    "snmpcheck": ToolInfo(
        name="snmpcheck",
        description="SNMP security scanner",
        usage="snmpcheck <target>"
    ),
    "snmpenum": ToolInfo(
        name="snmpenum",
        description="SNMP enumeration tool",
        usage="snmpenum <target>"
    ),
    "snmpbrute": ToolInfo(
        name="snmpbrute",
        description="SNMP brute-forcer tool",
        usage="snmpbrute <target>"
    ),
    "masscan": ToolInfo(
        name="masscan",
        description="Fast TCP port scanner",
        usage="masscan <target> -p <ports>"
    ),
    "covenant": ToolInfo(
        name="covenant",
        description="C2 framework for red teaming and penetration testing",
        usage="covenant"
    ),
    "impacket": ToolInfo(
        name="impacket",
        description="Python library for network protocols",
        usage="impacket-smbclient <username>@<target>"
    ),
    "cain": ToolInfo(
        name="cain",
        description="Password recovery tool",
        usage="cain"
    ),
    "ettercap-graphical": ToolInfo(
        name="ettercap-graphical",
        description="Graphical version of ettercap",
        usage="ettercap -G"
    ),
    "mitmproxy": ToolInfo(
        name="mitmproxy",
        description="Interactive HTTPS proxy",
        usage="mitmdump -s script.py"
    ),
    "dnschef": ToolInfo(
        name="dnschef",
        description="DNS server for penetration testing",
        usage="dnschef --interface <interface>"
    ),
    "sslstrip2": ToolInfo(
        name="sslstrip2",
        description="HTTPS stripping tool",
        usage="sslstrip2 -l <port>"
    ),
    "yamato": ToolInfo(
        name="yamato",
        description="Network security scanner",
        usage="yamato -t <target>"
    ),
    "cuckoo": ToolInfo(
        name="cuckoo",
        description="Malware analysis framework",
        usage="cuckoo"
    ),
    "volatility": ToolInfo(
        name="volatility",
        description="Memory forensics framework",
        usage="volatility -f <memory_dump> imageinfo"
    ),
    "radare2": ToolInfo(
        name="radare2",
        description="Reverse engineering framework",
        usage="r2 <binary_file>"
    ),
    "binwalk": ToolInfo(
        name="binwalk",
        description="Firmware analysis tool",
        usage="binwalk <firmware_file>"
    ),
    "exiftool": ToolInfo(
        name="exiftool",
        description="Metadata extraction tool",
        usage="exiftool <file>"
    ),
    "foremost": ToolInfo(
        name="foremost",
        description="Data recovery tool",
        usage="foremost -t <type> -i <image_file>"
    ),
    "photorec": ToolInfo(
        name="photorec",
        description="Data recovery tool",
        usage="photorec <image_file>"
    ),
    "john": ToolInfo(
        name="john",
        description="Password cracker",
        usage="john <hash_file>"
    ),
    "hydra": ToolInfo(
        name="hydra",
        description="Network login cracker supporting multiple protocols",
        usage="hydra [options] <target> <service>"
    ),
    "medusa": ToolInfo(
        name="medusa",
        description="Network login cracker",
        usage="medusa -H <target> -u <username> -p <password>"
    ),
    "nc": ToolInfo(
        name="nc",
        description="Netcat - network utility for reading and writing data",
        usage="nc <target> <port>"
    ),
    "ncat": ToolInfo(
        name="ncat",
        description="Netcat - network utility for reading and writing data",
        usage="ncat <target> <port>"
    ),
    "tcpdump": ToolInfo(
        name="tcpdump",
        description="Packet analyzer",
        usage="tcpdump -i <interface>"
    ),
    "wireshark": ToolInfo(
        name="wireshark",
        description="Network protocol analyzer",
        usage="wireshark"
    ),
    "ettercap": ToolInfo(
        name="ettercap",
        description="Man-in-the-middle attack tool",
        usage="ettercap -G"
    ),
    "dsniff": ToolInfo(
        name="dsniff",
        description="Network auditing and penetration testing tool",
        usage="dsniff -i <interface>"
    ),
    "arpspoof": ToolInfo(
        name="arpspoof",
        description="ARP spoofing tool",
        usage="arpspoof -i <interface> -t <target_ip> <gateway_ip>"
    ),
    "dnsspoof": ToolInfo(
        name="dnsspoof",
        description="DNS spoofing tool",
        usage="dnsspoof -i <interface>"
    ),
    "sslstrip": ToolInfo(
        name="sslstrip",
        description="HTTPS stripping tool",
        usage="sslstrip -l <port>"
    ),
    "yersinia": ToolInfo(
        name="yersinia",
        description="Network protocol attack tool",
        usage="yersinia -G"
    ),
    "recon-ng": ToolInfo(
        name="recon-ng",
        description="Web reconnaissance framework",
        usage="recon-ng"
    ),
    "maltego": ToolInfo(
        name="maltego",
        description="Link analysis and data mining tool",
        usage="maltego"
    ),
    "theharvester": ToolInfo(
        name="theharvester",
        description="Reconnaissance tool for email and subdomain harvesting",
        usage="theharvester -d <domain> -l 50 -b all"
    ),
    "dnsrecon": ToolInfo(
        name="dnsrecon",
        description="DNS enumeration tool",
        usage="dnsrecon -d <domain>"
    ),
    "nbtscan": ToolInfo(
        name="nbtscan",
        description="NBT scanner for Windows hosts and SMB shares",
        usage="nbtscan <target>"
    ),
    "onesixtyone": ToolInfo(
        name="onesixtyone",
        description="SNMP scanner for discovering devices and community strings",
        usage="onesixtyone <target>"
    ),
    "sslscan": ToolInfo(
        name="sslscan",
        description="SSL/TLS client and server scanner",
        usage="sslscan <target>"
    ),
    "wafw00f": ToolInfo(
        name="wafw00f",
        description="Web Application Firewall detection tool",
        usage="wafw00f <target>"
    ),
    "whatweb": ToolInfo(
        name="whatweb",
        description="Website fingerprinter",
        usage="whatweb <target>"
    ),
    "wpscan": ToolInfo(
        name="wpscan",
        description="WordPress security scanner",
        usage="wpscan --url <target>"
    ),
    "zmap": ToolInfo(
        name="zmap",
        description="Fast network scanner",
        usage="zmap -p <port> <target>"
    ),
    "dnsenum": ToolInfo(
        name="dnsenum",
        description="DNS enumeration tool",
        usage="dnsenum <domain>"
    ),
    "dnsscan": ToolInfo(
        name="dnsscan",
        description="DNS scanning tool",
        usage="dnsscan <domain>"
    ),
    "dnsx": ToolInfo(
        name="dnsx",
        description="DNS resolution tool",
        usage="dnsx -d <domain>"
    ),
    "nuclei": ToolInfo(
        name="nuclei",
        description="Fast and customizable vulnerability scanner",
        usage="nuclei -u <target> -t /usr/share/nuclei-templates/"
    ),
    "sqlninja": ToolInfo(
        name="sqlninja",
        description="SQL injection tool",
        usage="sqlninja -u <url>"
    ),
    "xsser": ToolInfo(
        name="xsser",
        description="XSS vulnerability scanner",
        usage="xsser -u <url>"
    ),
    "yamato": ToolInfo(
        name="yamato",
        description="Network security scanner",
        usage="yamato -t <target>"
    ),
    "zap-cli": ToolInfo(
        name="zap-cli",
        description="Command line interface for OWASP ZAP",
        usage="zap-cli quick-scan --self-contained <target>"
    ),
    "hashcat": ToolInfo(
        name="hashcat",
        description="Advanced password recovery tool",
        usage="hashcat -m <mode> <hash_file> <wordlist>"
    ),
    "john": ToolInfo(
        name="john",
        description="Password cracker",
        usage="john <hash_file>"
    ),
    "medusa": ToolInfo(
        name="medusa",
        description="Network login cracker",
        usage="medusa -H <target> -u <username> -p <password>"
    ),
    "smbclient": ToolInfo(
        name="smbclient",
        description="SMB/CIFS client for accessing SMB/CIFS shares",
        usage="smbclient -L <target>"
    ),
    "smbmap": ToolInfo(
        name="smbmap",
        description="SMB enumeration tool",
        usage="smbmap -H <target>"
    ),
    "enum4linux": ToolInfo(
        name="enum4linux",
        description="Enumerates information from Windows and Samba systems",
        usage="enum4linux <target>"
    ),
    "rpcclient": ToolInfo(
        name="rpcclient",
        description="RPC client for Windows systems",
        usage="rpcclient -U <username> <target>"
    ),
    "smbget": ToolInfo(
        name="smbget",
        description="SMB file download tool",
        usage="smbget -R -u <username> -p <password> -s <target>"
    ),
    "smbpasswd": ToolInfo(
        name="smbpasswd",
        description="Samba password management tool",
        usage="smbpasswd -a <username>"
    ),
    "mssqlclient": ToolInfo(
        name="mssqlclient",
        description="MSSQL client tool",
        usage="mssqlclient <username>@<target>"
    ),
    "mysql": ToolInfo(
        name="mysql",
        description="MySQL client tool",
        usage="mysql -h <target> -u <username> -p"
    ),
    "postgresql": ToolInfo(
        name="postgresql",
        description="PostgreSQL client tool",
        usage="psql -h <target> -U <username>"
    ),
    "ldapsearch": ToolInfo(
        name="ldapsearch",
        description="LDAP search tool",
        usage="ldapsearch -x -H ldap://<target> -b <base_dn>"
    ),
    "snmpwalk": ToolInfo(
        name="snmpwalk",
        description="SNMP walk tool",
        usage="snmpwalk -v 2c -c public <target>"
    ),
    "snmpcheck": ToolInfo(
        name="snmpcheck",
        description="SNMP security scanner",
        usage="snmpcheck <target>"
    ),
    "snmpenum": ToolInfo(
        name="snmpenum",
        description="SNMP enumeration tool",
        usage="snmpenum <target>"
    ),
    "snmpbrute": ToolInfo(
        name="snmpbrute",
        description="SNMP brute-forcer tool",
        usage="snmpbrute <target>"
    ),
    "cme": ToolInfo(
        name="crackmapexec",
        description="Post-exploitation tool for Windows environments",
        usage="crackmapexec <target> -u <username> -p <password>"
    ),
    "impacket": ToolInfo(
        name="impacket",
        description="Python library for network protocols",
        usage="impacket-smbclient <username>@<target>"
    ),
    "cain": ToolInfo(
        name="cain",
        description="Password recovery tool",
        usage="cain"
    ),
    "ettercap-graphical": ToolInfo(
        name="ettercap-graphical",
        description="Graphical version of ettercap",
        usage="ettercap -G"
    ),
    "mitmproxy": ToolInfo(
        name="mitmproxy",
        description="Interactive HTTPS proxy",
        usage="mitmdump -s script.py"
    ),
    "dnschef": ToolInfo(
        name="dnschef",
        description="DNS server for penetration testing",
        usage="dnschef --interface <interface>"
    ),
    "sslstrip2": ToolInfo(
        name="sslstrip2",
        description="HTTPS stripping tool",
        usage="sslstrip2 -l <port>"
    ),
    "covenant": ToolInfo(
        name="covenant",
        description="C2 framework for red teaming and penetration testing",
        usage="covenant"
    ),
    "empire": ToolInfo(
        name="empire",
        description="Post-exploitation framework",
        usage="empire"
    ),
    "maltego": ToolInfo(
        name="maltego",
        description="Link analysis and data mining tool",
        usage="maltego"
    ),
    "radare2": ToolInfo(
        name="radare2",
        description="Reverse engineering framework",
        usage="r2 <binary_file>"
    ),
    "binwalk": ToolInfo(
        name="binwalk",
        description="Firmware analysis tool",
        usage="binwalk <firmware_file>"
    ),
    "exiftool": ToolInfo(
        name="exiftool",
        description="Metadata extraction tool",
        usage="exiftool <file>"
    ),
    "foremost": ToolInfo(
        name="foremost",
        description="Data recovery tool",
        usage="foremost -t <type> -i <image_file>"
    ),
    "photorec": ToolInfo(
        name="photorec",
        description="Data recovery tool",
        usage="photorec <image_file>"
    ),
    "volatility": ToolInfo(
        name="volatility",
        description="Memory forensics framework",
        usage="volatility -f <memory_dump> imageinfo"
    ),
    "cuckoo": ToolInfo(
        name="cuckoo",
        description="Malware analysis framework",
        usage="cuckoo"
    ),
    "hashcat": ToolInfo(
        name="hashcat",
        description="Advanced password recovery tool",
        usage="hashcat -m <mode> <hash_file> <wordlist>"
    ),
    "john": ToolInfo(
        name="john",
        description="Password cracker",
        usage="john <hash_file>"
    ),
    "medusa": ToolInfo(
        name="medusa",
        description="Network login cracker",
        usage="medusa -H <target> -u <username> -p <password>"
    ),
    "nc": ToolInfo(
        name="nc",
        description="Netcat - network utility for reading and writing data",
        usage="nc <target> <port>"
    ),
    "ncat": ToolInfo(
        name="ncat",
        description="Netcat - network utility for reading and writing data",
        usage="ncat <target> <port>"
    ),
    "tcpdump": ToolInfo(
        name="tcpdump",
        description="Packet analyzer",
        usage="tcpdump -i <interface>"
    ),
    "wireshark": ToolInfo(
        name="wireshark",
        description="Network protocol analyzer",
        usage="wireshark"
    ),
    "dsniff": ToolInfo(
        name="dsniff",
        description="Network auditing and penetration testing tool",
        usage="dsniff -i <interface>"
    ),
    "arpspoof": ToolInfo(
        name="arpspoof",
        description="ARP spoofing tool",
        usage="arpspoof -i <interface> -t <target_ip> <gateway_ip>"
    ),
    "dnsspoof": ToolInfo(
        name="dnsspoof",
        description="DNS spoofing tool",
        usage="dnsspoof -i <interface>"
    ),
    "responder": ToolInfo(
        name="responder",
        description="LLMNR, NBT-NS and MDNS poisoner",
        usage="responder -I <interface>"
    ),
    "bettercap": ToolInfo(
        name="bettercap",
        description="Man-in-the-middle attack framework",
        usage="bettercap -iface <interface> -eval 'set http.proxy.response.headers.X-Forwarded-For 127.0.0.1'"
    ),
    "ettercap": ToolInfo(
        name="ettercap",
        description="Man-in-the-middle attack tool",
        usage="ettercap -G"
    ),
    "yamato": ToolInfo(
        name="yamato",
        description="Network security scanner",
        usage="yamato -t <target>"
    ),
    "zaproxy": ToolInfo(
        name="zap",
        description="Web application security scanner",
        usage="zap.sh"
    ),
    "covenant": ToolInfo(
        name="covenant",
        description="C2 framework for red teaming and penetration testing",
        usage="covenant"
    ),
    "empire": ToolInfo(
        name="empire",
        description="Post-exploitation framework",
        usage="empire"
    ),
    "maltego": ToolInfo(
        name="maltego",
        description="Link analysis and data mining tool",
        usage="maltego"
    ),
    "radare2": ToolInfo(
        name="radare2",
        description="Reverse engineering framework",
        usage="r2 <binary_file>"
    ),
    "binwalk": ToolInfo(
        name="binwalk",
        description="Firmware analysis tool",
        usage="binwalk <firmware_file>"
    ),
    "exiftool": ToolInfo(
        name="exiftool",
        description="Metadata extraction tool",
        usage="exiftool <file>"
    ),
    "foremost": ToolInfo(
        name="foremost",
        description="Data recovery tool",
        usage="foremost -t <type> -i <image_file>"
    ),
    "photorec": ToolInfo(
        name="photorec",
        description="Data recovery tool",
        usage="photorec <image_file>"
    ),
    "volatility": ToolInfo(
        name="volatility",
        description="Memory forensics framework",
        usage="volatility -f <memory_dump> imageinfo"
    ),
    "cuckoo": ToolInfo(
        name="cuckoo",
        description="Malware analysis framework",
        usage="cuckoo"
    ),
}

@app.get("/")
async def root():
    return {
        "message": "Kali Linux MCP Server",
        "version": "1.0.0",
        "tools_available": list(TOOLS.keys())
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
        dangerous_commands = ['rm', 'mv', 'cp', 'chmod', 'chown']
        for cmd in dangerous_commands:
            if cmd in request.command.lower():
                raise HTTPException(status_code=400, detail=f"Command '{cmd}' is not allowed")
        
        # Execute the command
        result = subprocess.run(
            request.command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=request.timeout
        )
        
        logger.info(f"Command executed successfully with return code: {result.returncode}")
        
        response = CommandResponse(
            output=result.stdout,
            error=result.stderr if result.stderr else None,
            returncode=result.returncode
        )
        
        return response
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Command execution timed out")
    except subprocess.SubprocessError as e:
        raise HTTPException(status_code=500, detail=f"Subprocess error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error executing command: {str(e)}")

@app.post("/execute_batch")
async def execute_batch_commands(commands: List[CommandRequest]):
    results = []
    
    for cmd_req in commands:
        try:
            logger.info(f"Executing batch command: {cmd_req.command}")
            
            # Limit dangerous commands
            dangerous_commands = ['rm', 'mv', 'cp', 'chmod', 'chown']
            for cmd in dangerous_commands:
                if cmd in cmd_req.command.lower():
                    results.append({
                        "command": cmd_req.command,
                        "output": "",
                        "error": f"Command '{cmd}' is not allowed",
                        "returncode": 1
                    })
                    continue
            
            result = subprocess.run(
                cmd_req.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=cmd_req.timeout
            )
            
            results.append({
                "command": cmd_req.command,
                "output": result.stdout,
                "error": result.stderr if result.stderr else None,
                "returncode": result.returncode
            })
            
        except Exception as e:
            results.append({
                "command": cmd_req.command,
                "output": "",
                "error": str(e),
                "returncode": -1
            })
    
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
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "output": "",
            "error": f"Command timed out after {timeout} seconds",
            "returncode": -1
        }
    except Exception as e:
        return {"output": "", "error": str(e), "returncode": -1}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3001)