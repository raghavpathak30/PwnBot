"""
Tool output parsing and exploit suggestion.
"""

import re
import subprocess
import shlex
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from .config import SEARCHSPLOIT_TIMEOUT

console = Console(highlight=False)


def parse_tool_output(command: str, output: str) -> Optional[str]:
    """Parse tool output and extract structured insights."""
    if not output:
        return None
    
    if "nmap" in command.lower():
        return parse_nmap_output(output)
    elif "gobuster" in command.lower():
        return parse_gobuster_output(output)
    elif "ffuf" in command.lower():
        return parse_ffuf_output(output)
    
    return None


def parse_nmap_output(output: str) -> Optional[str]:
    """Extract structured insights from nmap output."""
    lines = output.split("\n")
    
    open_ports = []
    services = []
    os_guess = None
    
    for line in lines:
        # Extract open ports
        if re.search(r"\d+/(tcp|udp)\s+open", line):
            match = re.search(r"(\d+/(tcp|udp))\s+open\s+(.+)", line)
            if match:
                port_proto = match.group(1)
                service = match.group(3).split()[0] if match.group(3) else "?"
                open_ports.append(port_proto)
                services.append(f"{port_proto} {service}")
        
        # Extract OS info
        if "OS:" in line or "Running:" in line or "OS CPE:" in line:
            if os_guess is None:
                os_guess = line.strip()
    
    if not open_ports and not os_guess:
        return None
    
    result = "[NMAP SUMMARY]\n"
    if open_ports:
        result += f"Open ports: {', '.join(open_ports)}\n"
    if services:
        result += f"Services: {', '.join(services)}\n"
    if os_guess:
        result += f"OS info: {os_guess}"
    
    return result.strip()


def parse_gobuster_output(output: str) -> Optional[str]:
    """Extract structured insights from gobuster output."""
    lines = output.split("\n")
    
    found_200 = []
    found_301_302 = []
    found_403 = []
    
    for line in lines:
        if "Status:" in line:
            # Extract path and status
            path_match = re.search(r"(/[^\s]*)", line)
            status_match = re.search(r"Status: (\d+)", line)
            
            if path_match and status_match:
                path = path_match.group(1)
                status = status_match.group(1)
                
                if status == "200":
                    found_200.append(path)
                elif status in ["301", "302"]:
                    found_301_302.append(path)
                elif status == "403":
                    found_403.append(path)
    
    if not found_200 and not found_301_302 and not found_403:
        return None
    
    result = "[GOBUSTER SUMMARY]\n"
    if found_200:
        result += f"Found (200): {', '.join(found_200)}\n"
    if found_301_302:
        result += f"Redirects (301/302): {', '.join(found_301_302)}\n"
    if found_403:
        result += f"Forbidden (403): {', '.join(found_403)}"
    
    return result.strip()


def parse_ffuf_output(output: str) -> Optional[str]:
    """Extract structured insights from ffuf output."""
    lines = output.split("\n")
    
    status_groups = {}
    
    for line in lines:
        if "[Status:" in line:
            # Extract status code and URL
            status_match = re.search(r"\[Status: (\d+)", line)
            url_match = re.search(r"(https?://[^\s]+)", line)
            
            if status_match:
                status = status_match.group(1)
                url = url_match.group(1) if url_match else "?"
                
                if status not in status_groups:
                    status_groups[status] = []
                status_groups[status].append(url)
    
    if not status_groups:
        return None
    
    result = "[FFUF SUMMARY]\n"
    for status in sorted(status_groups.keys()):
        urls = status_groups[status]
        result += f"{status}: {', '.join(urls)}\n"
    
    return result.strip()


def suggest_exploits(parsed_output: str, original_output: str) -> None:
    """Suggest exploits using searchsploit based on service versions."""
    # Check if searchsploit is available
    try:
        result = subprocess.run(
            ["which", "searchsploit"],
            capture_output=True,
            timeout=5
        )
        if result.returncode != 0:
            console.print("[dim]searchsploit not found — skipping exploit suggestions[/dim]")
            return
    except Exception:
        console.print("[dim]searchsploit not found — skipping exploit suggestions[/dim]")
        return
    
    # Extract service+version patterns
    patterns = [
        r"(Apache|nginx|IIS|Tomcat|JBoss|Jetty)[^\d]*([\d]+\.[\d.]+)",
        r"(OpenSSH|vsftpd|Exim|Postfix|Sendmail)[^\d]*([\d]+\.[\d.]+)",
        r"(MySQL|MariaDB|PostgreSQL|MongoDB)[^\d]*([\d]+\.[\d.]+)",
        r"(PHP|Python|Node\.js|Ruby)[^\d]*([\d]+\.[\d.]+)",
    ]
    
    services_found = set()
    for pattern in patterns:
        for match in re.finditer(pattern, original_output, re.IGNORECASE):
            service = match.group(1)
            version = match.group(2)
            services_found.add((service, version))
            if len(services_found) >= 5:
                break
        if len(services_found) >= 5:
            break
    
    if not services_found:
        return
    
    all_results = []
    
    for service, version in list(services_found)[:5]:
        try:
            result = subprocess.run(
                shlex.split(f"searchsploit {service} {version} --no-colour"),
                capture_output=True,
                text=True,
                timeout=SEARCHSPLOIT_TIMEOUT,
                shell=False
            )
            if result.stdout.strip():
                all_results.append(f"\n{service} {version}:\n{result.stdout}")
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
    
    if all_results:
        exploit_text = "[EXPLOIT SUGGESTIONS]\n" + "".join(all_results)
        exploit_panel = Panel(
            exploit_text,
            title="Exploit Suggestions (searchsploit)",
            border_style="red",
            style="dim"
        )
        console.print(exploit_panel)
    else:
        console.print("[dim]No searchsploit matches found[/dim]")
