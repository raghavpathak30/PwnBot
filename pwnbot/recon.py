"""
Reconnaissance and command execution functions.
"""

import os
import shlex
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from .llm import call_groq_api
from .parsers import parse_tool_output, suggest_exploits
from .reporting import log_exchange
from .state import ConversationManager, TargetState

console = Console(highlight=False)


def handle_run(
    command: str,
    target_state: TargetState,
    conversation_manager: ConversationManager,
    groq_client,
    active_model: str,
    available_models: list,
    session_log_path: Optional[Path],
) -> tuple:
    """
    Handle /run command for local shell execution.
    
    Returns:
        Tuple of (active_model, available_models)
    """
    if not command.strip():
        console.print("[dim yellow]Usage: /run <command>[/dim yellow]")
        console.print("[dim yellow]Example: /run nmap -sV -sC 10.10.11.20[/dim yellow]")
        return active_model, available_models
    
    # Warn if pipe, redirect, or semicolon detected
    if "|" in command or ">" in command or ";" in command:
        console.print("[yellow]Note: pipes, redirects and semicolons are not supported with /run — run complex commands in a separate terminal[/yellow]")
        return active_model, available_models
    
    console.print(f"[dim yellow]Running: {command}[/dim yellow]")
    
    # Parse command safely
    try:
        args = shlex.split(command)
    except ValueError as e:
        console.print(f"[bold red]Command parse error: {e}[/bold red]")
        return active_model, available_models
    
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
                return active_model, available_models
        
        if not stdout and not stderr:
            console.print("[yellow]Command produced no output[/yellow]")
            return active_model, available_models
        
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
            return active_model, available_models
        
        if context.strip():
            final_message = output_block + "\n\n" + context.strip()
        else:
            final_message = output_block
        
        # Create history message (truncated)
        history_message = f"[/run output: {command[:50]}{'...' if len(command) > 50 else ''}]"
        
        # Call API
        response, active_model, available_models = call_groq_api(
            final_message,
            conversation_manager,
            groq_client,
            active_model,
            available_models,
            history_message=history_message
        )
        
        if response:
            log_exchange(history_message, response, session_log_path)
        
        return active_model, available_models
    
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        return active_model, available_models


def handle_shell(command: str) -> None:
    """Handle /shell command for interactive shell execution."""
    if not command.strip():
        console.print("[dim yellow]Usage: /shell <command>[/dim yellow]")
        console.print("[dim yellow]Examples:[/dim yellow]")
        console.print("[dim yellow]  /shell nc -lvnp 4444[/dim yellow]")
        console.print("[dim yellow]  /shell pwncat-cs -lp 4444[/dim yellow]")
        console.print("[dim yellow]  /shell python3 -c 'import pty; pty.spawn(\"/bin/bash\")'[/dim yellow]")
        return
    console.print(f"[dim yellow]Launching interactive shell: {command}[/dim yellow]")
    console.print("[dim]Press Ctrl+C to return to PWNBOT[/dim]")
    try:
        os.system(command)
    except KeyboardInterrupt:
        pass
    console.print("[dim yellow]Returned to PWNBOT[/dim yellow]")


def run_auto_recon(
    ip: str,
    target_state: TargetState,
    conversation_manager: ConversationManager,
    groq_client,
    active_model: str,
    available_models: list,
    session_log_path: Optional[Path],
) -> tuple:
    """
    Run automated nmap recon on target IP and send results to PWNBOT.
    
    Returns:
        Tuple of (active_model, available_models)
    """
    console.print(f"[dim yellow]Starting auto recon on {ip}...[/dim yellow]")
    is_root = os.geteuid() == 0
    
    nmap_commands = [
        f"nmap -sV -sC --open -T4 {ip}",
        f"nmap -p- --min-rate 5000 -T4 {ip}",
    ]
    if is_root:
        nmap_commands.append(f"nmap -sU --top-ports 20 {ip}")
    
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
    response, active_model, available_models = call_groq_api(
        combined_output,
        conversation_manager,
        groq_client,
        active_model,
        available_models,
        history_message=history_message
    )
    
    if response:
        log_exchange(history_message, response, session_log_path)
    
    console.print("[green]Auto recon complete.[/green]")
    return active_model, available_models
