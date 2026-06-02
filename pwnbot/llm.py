"""
Groq API client initialization and LLM communication with model failover.
"""

import os
import sys
import time
from typing import List, Optional, Tuple

import requests
from groq import Groq, RateLimitError
from rich.console import Console
from rich.rule import Rule

from .config import MODEL_PRIORITY, MAX_TOKENS
from .state import ConversationManager

console = Console(highlight=False)


def init_groq_client() -> Optional[Groq]:
    """Initialize and return Groq client, or exit if API key not set."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        console.print(
            "[bold red]ERROR: GROQ_API_KEY environment variable not set[/bold red]"
        )
        console.print(
            "Set it with: [cyan]export GROQ_API_KEY='your-api-key'[/cyan]"
        )
        sys.exit(1)
    
    return Groq(api_key=api_key)


def fetch_available_models(groq_client: Groq) -> List[str]:
    """Fetch available models from Groq API."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        console.print(
            "[bold red]ERROR: GROQ_API_KEY environment variable not set[/bold red]"
        )
        return []
    
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


def call_groq_api(
    api_message: str,
    conversation_manager: ConversationManager,
    groq_client: Groq,
    active_model: str,
    available_models: List[str],
    history_message: Optional[str] = None,
) -> Tuple[Optional[str], str, List[str]]:
    """
    Call Groq API with conversation history and handle failover.
    
    Args:
        api_message: The actual message to send to the API
        conversation_manager: ConversationManager instance for history management
        groq_client: Groq client instance
        active_model: Currently active model ID
        available_models: List of available model IDs
        history_message: Optional shortened message for storing in history
    
    Returns:
        Tuple of (assistant_response, active_model, available_models)
        Returns (None, active_model, available_models) on error.
    """
    # Use history_message for stored history if provided, otherwise api_message
    store_message = history_message if history_message else api_message
    
    # Add user message to history
    conversation_manager.add_message("user", store_message)
    
    # Trim if necessary
    conversation_manager.trim_history()
    
    # Build system prompt
    system_prompt = conversation_manager.build_system_prompt()
    messages_with_system = (
        [{"role": "system", "content": system_prompt}]
        + conversation_manager.history[:-1]
        + [{"role": "user", "content": api_message}]
    )
    
    # Determine which model to use
    model_to_use = active_model
    
    while True:
        try:
            response = groq_client.chat.completions.create(
                model=model_to_use,
                messages=messages_with_system,
                max_tokens=MAX_TOKENS,
                stream=True,
            )
            
            assistant_message = ""
            console.print(Rule("PWNBOT", style="green"))
            for chunk in response:
                delta = chunk.choices[0].delta.content
                if delta:
                    assistant_message += delta
                    console.print(delta, end="")
            console.print()
            console.print(Rule(style="dim"))
            
            conversation_manager.add_message("assistant", assistant_message)
            
            return assistant_message, active_model, available_models
        
        except RateLimitError as e:
            # Handle 429 rate limit
            if model_to_use in available_models:
                available_models.remove(model_to_use)
            
            if not available_models:
                console.print(
                    f"[bold red]All models rate limited. Waiting 10 seconds...[/bold red]"
                )
                # Clean up orphaned user message
                if conversation_manager.history and conversation_manager.history[-1]["role"] == "user":
                    conversation_manager.history.pop()
                time.sleep(10)
                return None, active_model, available_models
            
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
            if conversation_manager.history and conversation_manager.history[-1]["role"] == "user":
                conversation_manager.history.pop()
            return None, active_model, available_models
