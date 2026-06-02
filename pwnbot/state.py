"""
State management classes for PwnBot.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from .config import BASE_PROMPT, MODE_REMINDERS

console = Console(highlight=False)


class TargetState:
    """Manages target information persistence and access."""
    
    def __init__(self):
        self.ip: Optional[str] = None
        self.domain: Optional[str] = None
        self.ports: List[str] = []
        self.notes: List[str] = []
        self.creds: List[str] = []
    
    def load(self) -> None:
        """Load target_state from session_target.json if it exists."""
        try:
            if Path("session_target.json").exists():
                with open("session_target.json", "r") as f:
                    loaded = json.load(f)
                    self.ip = loaded.get("ip")
                    self.domain = loaded.get("domain")
                    self.ports = loaded.get("ports", [])
                    self.notes = loaded.get("notes", [])
                    self.creds = loaded.get("creds", [])
        except Exception as e:
            console.print(f"[dim yellow]Warning: Failed to load session_target.json: {e}[/dim yellow]")
    
    def save(self) -> None:
        """Save target_state to session_target.json."""
        try:
            with open("session_target.json", "w") as f:
                json.dump({
                    "ip": self.ip,
                    "domain": self.domain,
                    "ports": self.ports,
                    "notes": self.notes,
                    "creds": self.creds,
                }, f, indent=2)
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to save session_target.json: {e}[/yellow]")
    
    def to_dict(self) -> Dict[str, Any]:
        """Return state as dictionary for serialization."""
        return {
            "ip": self.ip,
            "domain": self.domain,
            "ports": self.ports,
            "notes": self.notes,
            "creds": self.creds,
        }


class ConversationManager:
    """Manages conversation history, token estimation, and system prompt building."""
    
    MAX_TOKENS = 5000
    
    def __init__(self, target_state: TargetState, current_mode: str = "htb"):
        self.history: List[Dict[str, str]] = []
        self.target_state = target_state
        self.current_mode = current_mode
    
    def add_message(self, role: str, content: str) -> None:
        """Add a message to conversation history."""
        self.history.append({"role": role, "content": content})
    
    def estimate_tokens(self) -> float:
        """Estimate token count for current history."""
        return sum(len(msg.get("content", "")) / 4 for msg in self.history)
    
    def trim_history(self) -> None:
        """Trim conversation history if it exceeds token limit."""
        current_tokens = self.estimate_tokens()
        
        if current_tokens > self.MAX_TOKENS:
            console.print(
                "[dim]Trimming old context to stay within token limit...[/dim]"
            )
            # Keep the first message, remove oldest user+assistant pairs
            while current_tokens > self.MAX_TOKENS and len(self.history) > 2:
                if (self.history[0]["role"] == "user" and 
                        len(self.history) > 1 and
                        self.history[1]["role"] == "assistant"):
                    self.history.pop(0)
                    self.history.pop(0)
                else:
                    self.history.pop(0)
                current_tokens = self.estimate_tokens()
    
    def build_target_block(self) -> str:
        """Build the [CURRENT TARGET] block for system prompt."""
        ports_str = ",".join(map(str, self.target_state.ports)) if self.target_state.ports else "none"
        creds_str = ",".join(self.target_state.creds) if self.target_state.creds else "none"
        notes_str = "\n".join(self.target_state.notes) if self.target_state.notes else "none"
        
        return f"""[CURRENT TARGET]
IP: {self.target_state.ip or 'not set'}
Domain: {self.target_state.domain or 'not set'}
Open ports: {ports_str}
Credentials: {creds_str}
Notes: {notes_str}"""
    
    def build_system_prompt(self) -> str:
        """Dynamically build the system prompt."""
        system_prompt = BASE_PROMPT
        system_prompt += "\n\n" + MODE_REMINDERS[self.current_mode]
        
        # Check if any target field is non-empty
        if (
            self.target_state.ip
            or self.target_state.domain
            or self.target_state.ports
            or self.target_state.creds
            or self.target_state.notes
        ):
            system_prompt += "\n\n" + self.build_target_block()
        
        return system_prompt
    
    def clear(self) -> None:
        """Clear conversation history."""
        self.history = []
