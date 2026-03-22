#!/usr/bin/env python3
"""
PWNBOT - Elite Penetration Testing Chatbot
A specialized assistant for HTB, bug bounty, and authorized penetration testing.
"""

import os
import sys
import json
import re
import time
import subprocess
import shlex
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

import requests
from groq import Groq, RateLimitError
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
from rich.rule import Rule
from rich.table import Table
from duckduckgo_search import DDGS

# Initialize Rich console
console = Console()

# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

BASE_PROMPT = """You are PWNBOT — an elite penetration tester and bug bounty hunter. You think like an attacker, reason like a defender, and communicate like a senior red teamer writing a report.

## Identity
You are not a generic assistant. You are a specialist. Every response assumes the user is in a legal, authorized testing environment (HTB lab, personal scope, bug bounty program). You never add unnecessary disclaimers about ethics — the user knows. If something is clearly out of scope or illegal, say so once and move on.

## Core Expertise
- Web: SQLi (error/blind/time/OOB), XSS (stored/reflected/DOM/mutation), SSRF, XXE, SSTI (Jinja2/Twig/Freemarker), IDOR, OAuth misconfigs, JWT attacks, GraphQL introspection, deserialization, race conditions, HTTP request smuggling
- Network: nmap/masscan, service fingerprinting, SNMP, SMB, FTP, SMTP enum, DNS zone transfers, banner grabbing
- Linux privesc: SUID/SGID, sudo -l, writable paths, cron jobs, capabilities, NFS, weak permissions, env hijacking, wildcard injection
- Windows/AD: token impersonation, SeImpersonate, unquoted paths, registry autoruns, DLL hijacking, Kerberoasting, AS-REP roasting, Pass-the-Hash, Pass-the-Ticket, DCSync, BloodHound paths, LAPS bypass, GPO abuse
- Bug bounty recon chain: subfinder → httpx → gau/waybackurls → JS analysis → parameter discovery → nuclei → manual testing
- Report writing: PoC steps, impact statement, CVSS scoring, remediation recommendation

## Response Style
- Lead with the most likely / highest-value action first
- Provide exact, copy-paste ready commands with real flags — use realistic examples like 10.10.11.20 or target.com
- When explaining a technique follow this structure: What it is → Why it works → How to execute → What to look for in output
- Use markdown: code blocks for all commands/payloads, bold for key terms, headers for multi-step processes
- For HTB: think in phases — recon → foothold → lateral movement → privesc → loot
- For bug bounties: think in chains — single bugs rarely pay out; chain low-severity issues into critical

## Tool Fluency
Default stack:
- Recon: nmap, subfinder, amass, httpx, gau, waybackurls, katana
- Web: Burp Suite, ffuf, gobuster, feroxbuster, sqlmap, dalfox, nuclei
- AD/Windows: impacket, CrackMapExec, Responder, BloodHound, evil-winrm, Rubeus, Mimikatz, netexec
- Linux: LinPEAS, pspy, GTFOBins, pwncat-cs
- Password: hashcat (with correct mode flags), John, hydra
- Shell upgrade: python3 -c 'import pty;pty.spawn("/bin/bash")' then stty raw -echo; fg

## Web Search Context
When search results are provided at the top of the user message prefixed with [WEB SEARCH RESULTS], use them to inform your answer. Cite the source name when referencing a result.

## Session Awareness
When target context is provided under [CURRENT TARGET], always use the actual values in every command you write. Never use generic placeholders like <target> or <ip> when real values are available."""

MODE_REMINDERS = {
    "htb": "[MODE: HTB] Think in phases: recon → foothold → lateral movement → privesc → loot. Box is isolated. Be methodical.",
    "bugbounty": "[MODE: Bug Bounty] Stay in scope. Chain low findings into crits. Think impact, think report quality.",
    "recon": "[MODE: Recon] Focus on enumeration, asset discovery, and attack surface mapping before any exploitation.",
}

MODEL_PRIORITY = [
    "llama-3.3-70b-versatile",
    "openai/gpt-oss-120b",
    "llama-3.1-70b-versatile",
    "llama3-70b-8192",
    "llama-3.1-8b-instant",
]

# ============================================================================
# GLOBAL STATE
# ============================================================================

conversation_history: List[Dict[str, str]] = []
target_state: Dict[str, Any] = {
    "ip": None,
    "domain": None,
    "ports": [],
    "notes": [],
    "creds": [],
}
current_mode: str = "htb"
active_model: str = ""
available_models: List[str] = []
groq_client: Optional[Groq] = None
session_log_path: Optional[Path] = None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def print_banner():
    """Print the PWNBOT ASCII banner."""
    banner_text = Text()
    banner_text.append("    ╔═══════════════════════════════════╗\n", style="bold red")
    banner_text.append("    ║    🔴 PWNBOT 🔴    ║\n", style="bold yellow")
    banner_text.append("    ║   Elite Pentesting Companion   ║\n", style="bold red")
    banner_text.append("    ╚═══════════════════════════════════╝\n", style="bold red")
    console.print(banner_text)

    console.print(f"Current mode: {current_mode}")
    console.print(f"Active model: [dim]{active_model}[/dim]")
    console.print("Type [cyan]/help[/cyan] for commands")
    console.print(Rule(style="dim"))


def fetch_available_models() -> List[str]:
    """Fetch available models from Groq API."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        console.print(
            "[bold red]ERROR: GROQ_API_KEY environment variable not set[/bold red]"
        )
        console.print(
            "Set it with: [cyan]export GROQ_API_KEY='your-api-key'[/cyan]"
        )
        sys.exit(1)

    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        response = requests.get(
            "https://api.groq.com/openai/v1/models", headers=headers
        )
        response.raise_for_status()
        data = response.json()
        models = [model["id"] for model in data.get("data", [])]
        return models
    except Exception as e:
        console.print(f"[dim yellow]Warning: Failed to fetch models: {e}[/dim yellow]")
        return []


def select_model(available: List[str]) -> str:
    """Select model from priority list against available models."""
    for priority_model in MODEL_PRIORITY:
        if priority_model in available:
            return priority_model
    # Fallback
    return "llama-3.3-70b-versatile"


def build_target_block(target: Dict[str, Any]) -> str:
    """Build the [CURRENT TARGET] block for system prompt."""
    ports_str = ",".join(map(str, target["ports"])) if target["ports"] else "none"
    creds_str = ",".join(target["creds"]) if target["creds"] else "none"
    notes_str = "\n".join(target["notes"]) if target["notes"] else "none"

    return f"""[CURRENT TARGET]
IP: {target['ip'] or 'not set'}
Domain: {target['domain'] or 'not set'}
Open ports: {ports_str}
Credentials: {creds_str}
Notes: {notes_str}"""


def build_system_prompt() -> str:
    """Dynamically build the system prompt."""
    system_prompt = BASE_PROMPT
    system_prompt += "\n\n" + MODE_REMINDERS[current_mode]

    # Check if any target field is non-empty
    if (
        target_state["ip"]
        or target_state["domain"]
        or target_state["ports"]
        or target_state["creds"]
        or target_state["notes"]
    ):
        system_prompt += "\n\n" + build_target_block(target_state)

    return system_prompt


def estimate_tokens(messages: List[Dict[str, str]]) -> float:
    """Estimate token count for messages."""
    return sum(len(msg.get("content", "")) / 4 for msg in messages)


def trim_conversation_history() -> None:
    """Trim conversation history if it exceeds token limit."""
    max_tokens = 5000
    current_tokens = estimate_tokens(conversation_history)

    if current_tokens > max_tokens:
        console.print(
            "[dim]Trimming old context to stay within token limit...[/dim]"
        )
        # Keep the first message, remove oldest user+assistant pairs
        while current_tokens > max_tokens and len(conversation_history) > 2:
            conversation_history.pop(0)
            conversation_history.pop(0)
            current_tokens = estimate_tokens(conversation_history)


def initialize_logging() -> None:
    """Initialize session logging."""
    global session_log_path
    try:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        session_log_path = log_dir / f"session_{timestamp}.md"
    except Exception as e:
        console.print(f"[dim yellow]Warning: Could not create logs directory: {e}[/dim yellow]")


def log_exchange(user_msg: str, assistant_msg: str) -> None:
    """Log a user-assistant exchange to session log."""
    if not session_log_path:
        return

    try:
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"### [{timestamp}] You\n{user_msg}\n\n### [{timestamp}] PWNBOT\n{assistant_msg}\n\n"
        with open(session_log_path, "a") as f:
            f.write(log_entry)
    except Exception as e:
        console.print(f"[dim yellow]Warning: Failed to write to session log: {e}[/dim yellow]")


def load_target_state() -> None:
    """Load target_state from session_target.json if it exists."""
    global target_state
    try:
        if Path("session_target.json").exists():
            with open("session_target.json", "r") as f:
                loaded = json.load(f)
                target_state.update(loaded)
    except Exception as e:
        console.print(f"[dim yellow]Warning: Failed to load session_target.json: {e}[/dim yellow]")


def save_target_state() -> None:
    """Save target_state to session_target.json."""
    try:
        with open("session_target.json", "w") as f:
            json.dump(target_state, f, indent=2)
    except Exception as e:
        console.print(f"[yellow]Warning: Failed to save session_target.json: {e}[/yellow]")


def search_web(query: str) -> Optional[str]:
    """Perform a web search and return formatted results."""
    try:
        console.print("[yellow]Searching...[/yellow]", end="\r")
        results = DDGS().text(query, max_results=3)
        if not results:
            return None

        search_block = "[WEB SEARCH RESULTS]\n"
        for i, result in enumerate(results, 1):
            title = result.get("title", "")
            body = result.get("body", "")
            href = result.get("href", "")
            search_block += f"{i}. {title} — {body} (source: {href})\n"
        search_block += "---\n"
        return search_block
    except Exception as e:
        return None


def should_trigger_search(message: str) -> bool:
    """Check if message should trigger a web search."""
    message_lower = message.lower()

    # Check for trigger phrases
    if any(
        phrase in message_lower
        for phrase in ["search for", "look up"]
    ):
        return True

    # Check for CVE pattern (CVE-YYYY-NNNN)
    if re.search(r"cve-\d{4}-\d+", message_lower, re.IGNORECASE):
        return True

    # Check for version pattern (v1.2.3 only, not bare IPs)
    if re.search(r"v\d+\.\d+\.\d+", message):
        return True

    return False


def extract_search_query(message: str) -> str:
    """Extract a clean search query from the message."""
    message_lower = message.lower()

    # Try to extract from trigger phrases
    for phrase in ["search for", "look up"]:
        if phrase in message_lower:
            parts = message.split(phrase, 1)
            if len(parts) > 1:
                query = parts[1].strip().rstrip("?.")
                return " ".join(query.split()[:6])

    # Try to extract CVE
    cve_match = re.search(r"cve-\d{4}-\d+", message_lower, re.IGNORECASE)
    if cve_match:
        return cve_match.group(0)

    # Try to extract version
    version_match = re.search(r"v\d+\.\d+\.\d+", message)
    if version_match:
        words = message.split()
        for i, word in enumerate(words):
            if version_match.group(0) in word:
                start = max(0, i - 2)
                end = min(len(words), i + 3)
                return " ".join(words[start:end])

    return message[:100]


def handle_command(command: str) -> bool:
    """Handle slash commands. Returns True if a command was processed."""
    global conversation_history, current_mode, active_model, available_models
    
    parts = command.split(maxsplit=2)
    cmd = parts[0].lower()

    if cmd == "/clear":
        conversation_history = []
        print_banner()
        return True

    elif cmd == "/help":
        help_text = """
[bold cyan]Available Commands:[/bold cyan]

[bold]/clear[/bold] — Clear conversation history (preserve target & mode)
[bold]/help[/bold] — Show this help message
[bold]/exit, /quit[/bold] — Save target and exit
[bold]/history[/bold] — Show number of user turns
[bold]/target[/bold] — Display current target state
[bold]/set ip <value>[/bold] — Set target IP
[bold]/set domain <value>[/bold] — Set target domain
[bold]/set port <value>[/bold] — Add a port to target
[bold]/set creds <value>[/bold] — Add credentials
[bold]/note <text>[/bold] — Add a timestamped note
[bold]/save[/bold] — Save target state to session_target.json
[bold]/mode htb|bugbounty|recon[/bold] — Switch engagement mode
[bold]/model[/bold] — Show active model and availability
[bold]/model set <model_id>[/bold] — Switch to a specific model
[bold]/paste[/bold] — Paste multi-line content (type END on new line when done)
[bold]/run <command>[/bold] — Execute local shell command and send output to PWNBOT
[bold]/recon[/bold] — Manually trigger auto recon on current target IP
"""
        console.print(help_text)
        return True

    elif cmd == "/exit" or cmd == "/quit":
        save_target_state()
        console.print("[cyan]Target state saved. Goodbye![/cyan]")
        sys.exit(0)

    elif cmd == "/history":
        user_turns = len([m for m in conversation_history if m["role"] == "user"])
        console.print(f"User turns in history: {user_turns}")
        return True

    elif cmd == "/target":
        table = Table(title="Target State", show_header=True, header_style="bold")
        table.add_column("Field", style="cyan")
        table.add_column("Value")

        table.add_row("IP", str(target_state["ip"] or "not set"))
        table.add_row("Domain", str(target_state["domain"] or "not set"))
        table.add_row(
            "Open Ports", ",".join(map(str, target_state["ports"])) or "none"
        )
        table.add_row("Credentials", ",".join(target_state["creds"]) or "none")
        table.add_row(
            "Notes", "\n".join(target_state["notes"]) or "none"
        )

        console.print(table)
        return True

    elif cmd == "/set" and len(parts) < 3:
        console.print("[bold red]Usage: /set <ip|domain|port|creds> <value>[/bold red]")
        return True
    elif cmd == "/set" and len(parts) >= 3:
        subcommand = parts[1].lower()
        value = parts[2]

        if subcommand == "ip":
            target_state["ip"] = value
            console.print(f"[green]IP set to: {value}[/green]")
            save_target_state()
            # Ask for auto recon
            recon_choice = Prompt.ask(
                f"Run auto recon on {value}? (y/n)",
                default="n"
            )
            if recon_choice.strip().lower() in ["y", "yes"]:
                run_auto_recon(value)
        elif subcommand == "domain":
            target_state["domain"] = value
            console.print(f"[green]Domain set to: {value}[/green]")
            save_target_state()
        elif subcommand == "port":
            port = value
            if port not in target_state["ports"]:
                target_state["ports"].append(port)
                console.print(f"[green]Port added: {port}[/green]")
                save_target_state()
        elif subcommand == "creds":
            if value not in target_state["creds"]:
                target_state["creds"].append(value)
                console.print(f"[green]Credentials added: {value}[/green]")
                save_target_state()
        return True

    elif cmd == "/note" and len(parts) >= 2:
        note_text = " ".join(parts[1:])
        timestamp = datetime.now().strftime("%H:%M:%S")
        target_state["notes"].append(f"[{timestamp}] {note_text}")
        console.print(f"[green]Note added[/green]")
        save_target_state()
        return True

    elif cmd == "/save":
        save_target_state()
        console.print("[green]Target state saved[/green]")
        return True

    elif cmd == "/mode" and len(parts) >= 2:
        mode = parts[1].lower()
        if mode in MODE_REMINDERS:
            current_mode = mode
            console.print(f"[green]Mode switched to: {mode}[/green]")
        else:
            console.print(f"[bold red]Invalid mode. Use: htb, bugbounty, or recon[/bold red]")
        return True

    elif cmd == "/model":
        if len(parts) == 1:
            console.print(f"Active model: [cyan]{active_model}[/cyan]")
            console.print(f"Available models (ranked):")
            for i, model in enumerate(MODEL_PRIORITY, 1):
                marker = "[green]✓[/green]" if model in available_models else "[red]✗[/red]"
                console.print(f"  {marker} {i}. {model}")
        elif len(parts) == 2 and parts[1].lower() == "set":
            console.print("[bold red]Usage: /model set <model_id>[/bold red]")
        elif len(parts) >= 3 and parts[1].lower() == "set":
            model_id = parts[2]
            if model_id in available_models:
                old_model = active_model
                active_model = model_id
                console.print(f"[green]Model switched from {old_model} to {model_id}[/green]")
            else:
                console.print(
                    f"[bold red]Model not available. Valid options:[/bold red]"
                )
                for model in available_models:
                    console.print(f"  - {model}")
        return True

    elif cmd == "/paste":
        handle_paste()
        return True

    elif cmd == "/run":
        command = " ".join(parts[1:]) if len(parts) > 1 else ""
        handle_run(command)
        return True

    elif cmd == "/recon":
        if target_state["ip"]:
            run_auto_recon(target_state["ip"])
        else:
            console.print("[yellow]No target IP set. Use /set ip <value> first.[/yellow]")
        return True

    return False


def handle_paste() -> None:
    """Handle /paste command for multi-line input."""
    console.print("[dim cyan]Paste your content below. Type END on a new line when done:[/dim cyan]")
    
    lines: List[str] = []
    try:
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
    except KeyboardInterrupt:
        console.print("[yellow]Paste cancelled.[/yellow]")
        return
    
    pasted_content = "\n".join(lines)
    
    if not pasted_content.strip():
        console.print("[yellow]Warning: No content provided.[/yellow]")
        return
    
    # Ask for optional question
    question = Prompt.ask("Add a question about this content (or press Enter to skip)", default="")
    
    if question.strip():
        final_message = pasted_content + "\n\n" + question.strip()
    else:
        final_message = pasted_content
    
    # Create history message (truncated for readability)
    history_message = final_message[:100] + ("..." if len(final_message) > 100 else "")
    
    # Show thinking
    console.print("[dim]Thinking...[/dim]", end="\r")
    
    # Call API
    response = call_groq_api(final_message, history_message=history_message)
    
    # Clear thinking line
    console.print(" " * 40, end="\r")
    
    if response:
        # Display response in panel
        panel = Panel(
            Markdown(response),
            title="PWNBOT",
            border_style="green",
        )
        console.print(panel)
        
        # Log the exchange
        log_exchange(history_message, response)


def handle_run(command: str) -> None:
    """Handle /run command for local shell execution."""
    if not command.strip():
        console.print("[dim yellow]Usage: /run <command>[/dim yellow]")
        console.print("[dim yellow]Example: /run nmap -sV -sC 10.10.11.20[/dim yellow]")
        return
    
    # Warn if pipe, redirect, or semicolon detected
    if "|" in command or ">" in command or ";" in command:
        console.print("[yellow]Note: pipes, redirects and semicolons are not supported with /run — run complex commands in a separate terminal[/yellow]")
        return
    
    console.print(f"[dim yellow]Running: {command}[/dim yellow]")
    
    # Parse command safely
    try:
        args = shlex.split(command)
    except ValueError as e:
        console.print(f"[bold red]Command parse error: {e}[/bold red]")
        return
    
    try:
        with subprocess.Popen(
            args,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        ) as proc:
            try:
                stdout, stderr = proc.communicate(timeout=120)
                stdout = stdout.strip()
                stderr = stderr.strip()
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                console.print("[bold red]Command timed out after 120 seconds. Process killed.[/bold red]")
                return
        
        if not stdout and not stderr:
            console.print("[yellow]Command produced no output[/yellow]")
            return
        
        # Build output block with truncation
        output_block = f"[COMMAND OUTPUT]\n$ {command}\n"
        # Truncate stdout to 3000 chars
        stdout_display = stdout[:3000] + ("...[truncated]" if len(stdout) > 3000 else "")
        if stdout_display:
            output_block += stdout_display
        if stderr:
            if stdout_display:
                output_block += "\n"
            # Truncate stderr to 1000 chars
            stderr_display = stderr[:1000] + ("...[truncated]" if len(stderr) > 1000 else "")
            output_block += f"[STDERR]\n{stderr_display}"
        
        # Display output in panel
        panel = Panel(
            output_block,
            title="Output",
            border_style="cyan",
            style="dim"
        )
        console.print(panel)
        
        # Parse tool output for insights
        parsed_output = parse_tool_output(command, stdout)
        if parsed_output:
            insights_panel = Panel(
                parsed_output,
                title="Parsed Insights",
                border_style="yellow",
                style="dim"
            )
            console.print(insights_panel)
            
            # Suggest exploits if nmap
            if "nmap" in command.lower():
                suggest_exploits(parsed_output, stdout)
        
        # Ask if user wants to send to PWNBOT
        context = Prompt.ask(
            "Add context and press Enter to send, or type SKIP to cancel",
            default=""
        )
        
        if context.strip().upper() == "SKIP":
            console.print("[yellow]Cancelled — output not sent.[/yellow]")
            return
        
        if context.strip():
            final_message = output_block + "\n\n" + context.strip()
        else:
            final_message = output_block
        
        # Create history message (truncated)
        history_message = f"[/run output: {command[:50]}{'...' if len(command) > 50 else ''}]"
        
        # Show thinking
        console.print("[dim]Thinking...[/dim]", end="\r")
        
        # Call API
        response = call_groq_api(final_message, history_message=history_message)
        
        # Clear thinking line
        console.print(" " * 40, end="\r")
        
        if response:
            # Display response in panel
            panel = Panel(
                Markdown(response),
                title="PWNBOT",
                border_style="green",
            )
            console.print(panel)
            
            # Log the exchange
            log_exchange(history_message, response)
    
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")


def run_auto_recon(ip: str) -> None:
    """Run automated nmap recon on target IP and send results to PWNBOT."""
    console.print(f"[dim yellow]Starting auto recon on {ip}...[/dim yellow]")
    
    nmap_commands = [
        f"nmap -sV -sC --open -T4 {ip}",
        f"nmap -p- --min-rate 5000 -T4 {ip}",
        f"nmap -sU --top-ports 20 {ip}",
    ]
    
    results = []
    
    for nmap_cmd in nmap_commands:
        try:
            with subprocess.Popen(
                shlex.split(nmap_cmd),
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            ) as proc:
                try:
                    stdout, stderr = proc.communicate(timeout=180)
                    results.append((nmap_cmd, stdout.strip(), stderr.strip()))
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    results.append((nmap_cmd, "", "[TIMEOUT after 180 seconds]"))
        except Exception as e:
            results.append((nmap_cmd, "", f"[ERROR: {e}]"))
    
    # Build combined message
    combined_output = f"[AUTO RECON: {ip}]\n"
    for cmd, out, err in results:
        combined_output += f"\n=== {cmd} ===\n"
        # Truncate each output to 3000 chars to avoid token overflow
        output_block = out[:3000] + ("...[truncated]" if len(out) > 3000 else "")
        if output_block:
            combined_output += output_block
        if err:
            if output_block:
                combined_output += "\n"
            # Truncate error too
            err_block = err[:1000] + ("...[truncated]" if len(err) > 1000 else "")
            combined_output += f"[STDERR]\n{err_block}"
    
    # Send to API
    history_message = f"[auto recon: {ip}]"
    console.print("[dim]Processing results...[/dim]", end="\r")
    response = call_groq_api(combined_output, history_message=history_message)
    console.print(" " * 40, end="\r")
    
    if response:
        panel = Panel(
            Markdown(response),
            title="PWNBOT",
            border_style="green",
        )
        console.print(panel)
        log_exchange(history_message, response)
    
    console.print("[green]Auto recon complete.[/green]")


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
        r"(Apache|nginx|IIS|Tomcat|JBoss|Jetty)\s+([\d.]+)",
        r"(OpenSSH|vsftpd|Exim|Postfix|Sendmail)\s+([\d.]+)",
        r"(MySQL|MariaDB|PostgreSQL|MongoDB)\s+([\d.]+)",
        r"(PHP|Python|Node\.js|Ruby)\s+([\d.]+)",
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
                timeout=10
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


def call_groq_api(api_message: str, history_message: str = None) -> Optional[str]:
    """Call Groq API with conversation history and handle errors."""
    global conversation_history, active_model, available_models

    # Use history_message for stored history if provided, otherwise api_message
    store_message = history_message if history_message else api_message

    # Add user message to history
    conversation_history.append({"role": "user", "content": store_message})

    # Trim if necessary
    trim_conversation_history()

    # Build system prompt
    system_prompt = build_system_prompt()
    messages_with_system = [{"role": "system", "content": system_prompt}] + conversation_history[:-1] + [{"role": "user", "content": api_message}]

    # Determine which model to use
    model_to_use = active_model

    while True:
        try:
            response = groq_client.chat.completions.create(
                model=model_to_use,
                messages=messages_with_system,
                max_tokens=4096,
                stream=True,
            )

            assistant_message = ""
            for chunk in response:
                delta = chunk.choices[0].delta.content
                if delta:
                    assistant_message += delta
                    console.print(delta, end="", highlight=False)
            
            # Print blank line after streaming
            console.print()
            
            conversation_history.append({"role": "assistant", "content": assistant_message})

            return assistant_message

        except RateLimitError as e:
            # Handle 429 rate limit
            if model_to_use in available_models:
                available_models.remove(model_to_use)

            if not available_models:
                console.print(
                    f"[bold red]All models rate limited. Waiting 10 seconds...[/bold red]"
                )
                # Clean up orphaned user message
                if conversation_history and conversation_history[-1]["role"] == "user":
                    conversation_history.pop()
                time.sleep(10)
                return None

            next_model = select_model(available_models)

            console.print(
                f"[yellow]Rate limited on {model_to_use}, switching to {next_model}...[/yellow]"
            )
            active_model = next_model
            model_to_use = next_model
            continue

        except Exception as e:
            console.print(f"[bold red]API Error: {e}[/bold red]")
            # Remove the last user message to keep history clean
            if conversation_history and conversation_history[-1]["role"] == "user":
                conversation_history.pop()
            return None


def main():
    """Main chatbot loop."""
    global groq_client, active_model, available_models

    # Check for API key
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        console.print(
            "[bold red]ERROR: GROQ_API_KEY environment variable not set[/bold red]"
        )
        console.print(
            "Set it with: [cyan]export GROQ_API_KEY='your-api-key'[/cyan]"
        )
        sys.exit(1)

    # Initialize Groq client
    groq_client = Groq(api_key=api_key)

    # Fetch available models
    available_models = fetch_available_models()
    if not available_models:
        available_models = MODEL_PRIORITY

    # Select active model
    active_model = select_model(available_models)

    # Initialize logging and target state
    initialize_logging()
    load_target_state()

    # Print banner
    print_banner()

    # Main loop
    try:
        while True:
            try:
                user_input = Prompt.ask("[bold cyan]You[/bold cyan]").strip()
            except EOFError:
                # Handle end of input
                save_target_state()
                console.print("[cyan]Goodbye![/cyan]")
                break

            if not user_input:
                continue

            # Check for commands
            if user_input.startswith("/"):
                handle_command(user_input)
                continue

            # Original message for logging
            original_message = user_input

            # Check for web search
            if should_trigger_search(user_input):
                search_query = extract_search_query(user_input)
                search_results = search_web(search_query)
                if search_results:
                    user_input = search_results + original_message

            # Show thinking
            console.print("[dim]Thinking...[/dim]", end="\r")

            # Call API
            response = call_groq_api(user_input, history_message=original_message)

            # Clear thinking line (streaming already added newline)
            console.print(" " * 40, end="\r")

            if response:
                # Display response in panel
                panel = Panel(
                    Markdown(response),
                    title="PWNBOT",
                    border_style="green",
                )
                console.print(panel)

                # Log the exchange (with original message, not augmented)
                log_exchange(original_message, response)

    except KeyboardInterrupt:
        save_target_state()
        console.print("\n[cyan]Session interrupted. Target state saved. Goodbye![/cyan]")


if __name__ == "__main__":
    main()
