"""
Slash-command dispatcher and handlers.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from .config import MODE_REMINDERS, MODEL_PRIORITY
from .llm import call_groq_api
from .recon import handle_run, handle_shell, run_auto_recon
from .reporting import generate_report, log_exchange
from .state import ConversationManager, TargetState

console = Console(highlight=False)


def handle_paste(
    target_state: TargetState,
    conversation_manager: ConversationManager,
    groq_client,
    active_model: str,
    available_models: list,
    session_log_path: Optional[Path],
) -> Tuple[str, list]:
    """
    Handle /paste command for multi-line input.
    
    Returns:
        Tuple of (active_model, available_models)
    """
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
        return active_model, available_models
    
    pasted_content = "\n".join(lines)
    
    if not pasted_content.strip():
        console.print("[yellow]Warning: No content provided.[/yellow]")
        return active_model, available_models
    
    # Ask for optional question
    question = Prompt.ask("Add a question about this content (or press Enter to skip)", default="")
    
    if question.strip():
        final_message = pasted_content + "\n\n" + question.strip()
    else:
        final_message = pasted_content
    
    # Create history message (truncated for readability)
    history_message = final_message[:100] + ("..." if len(final_message) > 100 else "")
    
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


def handle_command(
    command: str,
    target_state: TargetState,
    conversation_manager: ConversationManager,
    groq_client,
    active_model: str,
    available_models: list,
    session_log_path: Optional[Path],
) -> Tuple[bool, str, list]:
    """
    Handle slash commands. 
    
    Returns:
        Tuple of (was_command_processed, active_model, available_models)
    """
    parts = command.split(maxsplit=2)
    cmd = parts[0].lower()
    
    if cmd == "/clear":
        conversation_manager.clear()
        return True, active_model, available_models
    
    elif cmd == "/help":
        table = Table(title="Help", show_header=True, header_style="bold")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        
        table.add_row("[bold]Session[/bold]", "")
        table.add_row("/clear", "Clear conversation history (preserve target & mode)")
        table.add_row("/help", "Show this help message")
        table.add_row("/history", "Show number of user turns")
        table.add_row("/report", "Generate markdown report from current session")
        table.add_row("/exit, /quit", "Save target and exit")
        
        table.add_section()
        table.add_row("[bold]Target[/bold]", "")
        table.add_row("/target", "Display current target state")
        table.add_row("/set ip <value>", "Set target IP")
        table.add_row("/set domain <value>", "Set target domain")
        table.add_row("/set port <value>", "Add a port to target")
        table.add_row("/set creds <value>", "Add credentials")
        table.add_row("/note <text>", "Add a timestamped note")
        table.add_row("/save", "Save target state to session_target.json")
        
        table.add_section()
        table.add_row("[bold]Execution[/bold]", "")
        table.add_row("/paste", "Paste multi-line content (type END on new line when done)")
        table.add_row("/run <command>", "Execute local shell command and send output to PWNBOT")
        table.add_row("/shell <command>", "Run interactive command (reverse shells, listeners, pwncat)")
        table.add_row("/recon", "Manually trigger auto recon on current target IP")
        
        table.add_section()
        table.add_row("[bold]Settings[/bold]", "")
        table.add_row("/mode htb|bugbounty|recon", "Switch engagement mode")
        table.add_row("/model", "Show active model and availability")
        table.add_row("/model set <model_id>", "Switch to a specific model")
        
        console.print(table)
        return True, active_model, available_models
    
    elif cmd == "/exit" or cmd == "/quit":
        target_state.save()
        console.print("[cyan]Target state saved. Goodbye![/cyan]")
        import sys
        sys.exit(0)
    
    elif cmd == "/history":
        user_turns = len([m for m in conversation_manager.history if m["role"] == "user"])
        console.print(f"User turns in history: {user_turns}")
        return True, active_model, available_models
    
    elif cmd == "/target":
        table = Table(title="Target State", show_header=True, header_style="bold")
        table.add_column("Field", style="cyan")
        table.add_column("Value")
        
        ip_value = str(target_state.ip or "not set")
        domain_value = str(target_state.domain or "not set")
        ports_value = ",".join(map(str, target_state.ports)) or "none"
        creds_value = ",".join(target_state.creds) or "none"
        notes_value = "\n".join(target_state.notes) or "none"
        
        def style_target_value(value: str) -> str:
            return f"[dim red]{value}[/dim red]" if value in {"not set", "none"} else f"[green]{value}[/green]"
        
        table.add_row("IP", style_target_value(ip_value))
        table.add_row("Domain", style_target_value(domain_value))
        table.add_row("Open Ports", style_target_value(ports_value))
        table.add_row("Credentials", style_target_value(creds_value))
        table.add_row("Notes", style_target_value(notes_value))
        
        console.print(table)
        return True, active_model, available_models
    
    elif cmd == "/set" and len(parts) < 3:
        console.print("[bold red]Usage: /set <ip|domain|port|creds> <value>[/bold red]")
        return True, active_model, available_models
    
    elif cmd == "/set" and len(parts) >= 3:
        subcommand = parts[1].lower()
        value = parts[2]
        
        if subcommand == "ip":
            target_state.ip = value
            console.print(f"[green]IP set to: {value}[/green]")
            target_state.save()
            # Ask for auto recon
            recon_choice = Prompt.ask(
                f"Run auto recon on {value}? (y/n)",
                default="n"
            )
            if recon_choice.strip().lower() in ["y", "yes"]:
                active_model, available_models = run_auto_recon(
                    value,
                    target_state,
                    conversation_manager,
                    groq_client,
                    active_model,
                    available_models,
                    session_log_path,
                )
        elif subcommand == "domain":
            target_state.domain = value
            console.print(f"[green]Domain set to: {value}[/green]")
            target_state.save()
        elif subcommand == "port":
            port = value
            if port not in target_state.ports:
                target_state.ports.append(port)
                console.print(f"[green]Port added: {port}[/green]")
                target_state.save()
        elif subcommand == "creds":
            if value not in target_state.creds:
                target_state.creds.append(value)
                console.print(f"[green]Credentials added: {value}[/green]")
                target_state.save()
        return True, active_model, available_models
    
    elif cmd == "/note" and len(parts) >= 2:
        note_text = " ".join(parts[1:])
        timestamp = datetime.now().strftime("%H:%M:%S")
        target_state.notes.append(f"[{timestamp}] {note_text}")
        console.print(f"[green]Note added[/green]")
        target_state.save()
        return True, active_model, available_models
    
    elif cmd == "/save":
        target_state.save()
        console.print("[green]Target state saved[/green]")
        return True, active_model, available_models
    
    elif cmd == "/mode" and len(parts) >= 2:
        mode = parts[1].lower()
        if mode in MODE_REMINDERS:
            conversation_manager.current_mode = mode
            console.print(f"[green]Mode switched to: {mode}[/green]")
        else:
            console.print(f"[bold red]Invalid mode. Use: htb, bugbounty, or recon[/bold red]")
        return True, active_model, available_models
    
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
        return True, active_model, available_models
    
    elif cmd == "/paste":
        active_model, available_models = handle_paste(
            target_state,
            conversation_manager,
            groq_client,
            active_model,
            available_models,
            session_log_path,
        )
        return True, active_model, available_models
    
    elif cmd == "/run":
        command = " ".join(parts[1:]) if len(parts) > 1 else ""
        active_model, available_models = handle_run(
            command,
            target_state,
            conversation_manager,
            groq_client,
            active_model,
            available_models,
            session_log_path,
        )
        return True, active_model, available_models
    
    elif cmd == "/shell":
        command = " ".join(parts[1:]) if len(parts) > 1 else ""
        handle_shell(command)
        return True, active_model, available_models
    
    elif cmd == "/recon":
        if target_state.ip:
            active_model, available_models = run_auto_recon(
                target_state.ip,
                target_state,
                conversation_manager,
                groq_client,
                active_model,
                available_models,
                session_log_path,
            )
        else:
            console.print("[yellow]No target IP set. Use /set ip <value> first.[/yellow]")
        return True, active_model, available_models
    
    elif cmd == "/report":
        generate_report(target_state, session_log_path)
        return True, active_model, available_models
    
    return False, active_model, available_models
