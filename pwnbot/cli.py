"""
CLI main loop and application initialization.
"""

import atexit
import os
import readline
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from .commands import handle_command
from .config import DEFAULT_MODE
from .llm import call_groq_api, fetch_available_models, init_groq_client, select_model
from .reporting import initialize_logging, log_exchange
from .search import extract_search_query, search_web, should_trigger_search
from .state import ConversationManager, TargetState

console = Console(highlight=False)


def print_banner(current_mode: str, active_model: str) -> None:
    """Print the PWNBOT banner."""
    console.print()
    mode_color = {
        "htb": "red",
        "bugbounty": "yellow",
        "recon": "blue",
    }.get(current_mode, "cyan")
    banner_text = (
        "[bold red]PWNBOT[/bold red]\n"
        f"Mode  : [{mode_color}]{current_mode}[/{mode_color}]\n"
        f"Model : [dim]{active_model}[/dim]\n"
        "Tip   : [cyan]Type /help for commands[/cyan]"
    )
    console.print(
        Panel(
            banner_text,
            title="[bold]Elite Pentesting Companion[/bold]",
            border_style="red",
            expand=False,
        )
    )
    console.print()


def main():
    """Main application loop."""
    # Initialize Groq client
    groq_client = init_groq_client()
    
    # Fetch available models
    available_models = fetch_available_models(groq_client)
    if not available_models:
        from .config import MODEL_PRIORITY
        available_models = MODEL_PRIORITY
    
    # Select active model
    active_model = select_model(available_models)
    
    # Initialize state
    target_state = TargetState()
    target_state.load()
    
    current_mode = DEFAULT_MODE
    conversation_manager = ConversationManager(target_state, current_mode)
    
    # Initialize logging (use workspace if already set)
    session_log_path = initialize_logging(target_state.workspace_dir)
    
    # Setup readline history
    history_file = os.path.expanduser("~/.pwnbot_history")
    try:
        readline.read_history_file(history_file)
    except FileNotFoundError:
        pass
    atexit.register(readline.write_history_file, history_file)
    readline.set_history_length(500)
    try:
        readline.set_completer(None)
    except Exception:
        pass
    
    # Print banner
    print_banner(current_mode, active_model)
    
    # Main loop
    try:
        while True:
            try:
                user_input = Prompt.ask("\n[bold cyan]You[/bold cyan]").strip()
            except EOFError:
                target_state.save()
                console.print("[cyan]Goodbye![/cyan]")
                break
            
            if not user_input:
                continue
            
            # Check for commands
            if user_input.startswith("/"):
                was_command, active_model, available_models, session_log_path = handle_command(
                    user_input,
                    target_state,
                    conversation_manager,
                    groq_client,
                    active_model,
                    available_models,
                    session_log_path,
                )
                if was_command:
                    # Update conversation manager's current_mode if it changed
                    continue
            
            # Original message for logging
            original_message = user_input
            
            # Check for web search
            if should_trigger_search(user_input):
                search_query = extract_search_query(user_input)
                search_results = search_web(search_query)
                if search_results:
                    user_input = search_results + original_message
            
            # Call API
            response, active_model, available_models = call_groq_api(
                user_input,
                conversation_manager,
                groq_client,
                active_model,
                available_models,
                history_message=original_message,
            )
            
            if response:
                log_exchange(original_message, response, session_log_path)
    
    except KeyboardInterrupt:
        target_state.save()
        console.print("\n[cyan]Session interrupted. Target state saved. Goodbye![/cyan]")


if __name__ == "__main__":
    main()
