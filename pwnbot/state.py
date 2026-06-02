"""
State management classes for PwnBot.
"""

import json
from pathlib import Path
import json
import re
import shutil
from typing import Any, Dict, List, Optional

from pathlib import Path

from rich.console import Console

from .config import BASE_PROMPT, MODE_REMINDERS, MAX_HISTORY_TOKENS

console = Console(highlight=False)


def _engagements_root() -> Path:
    root = Path.home() / ".pwnbot" / "engagements"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _sanitize_target(value: str) -> str:
    # Keep alphanumerics, dot, dash, underscore; replace others with underscore
    v = value.strip().lower()
    return re.sub(r"[^a-z0-9_.-]", "_", v)


class TargetState:
    """Manages target information persistence and access."""
    
    def __init__(self):
        self.ip: Optional[str] = None
        self.domain: Optional[str] = None
        self.ports: List[str] = []
        self.notes: List[str] = []
        self.creds: List[str] = []
        self.workspace_dir: Optional[Path] = None
    
    def load(self) -> None:
        """Load target_state from session_target.json if it exists."""
        try:
            cwd_session = Path("session_target.json")
            if cwd_session.exists():
                console.print("[dim]Found legacy session_target.json in current directory.[/dim]")
                resp = input("Import into workspace under ~/.pwnbot/engagements/? (y/n) ").strip().lower()
                with open(cwd_session, "r") as f:
                    loaded = json.load(f)
                self.ip = loaded.get("ip")
                self.domain = loaded.get("domain")
                self.ports = loaded.get("ports", [])
                self.notes = loaded.get("notes", [])
                self.creds = loaded.get("creds", [])

                if resp in ("y", "yes"):
                    # Create workspace and migrate files
                    self._ensure_workspace()
                    try:
                        # move session_target.json
                        shutil.move(str(cwd_session), str(self.workspace_dir / "target.json"))
                        # move logs/ if exists
                        if Path("logs").exists():
                            shutil.move("logs", str(self.workspace_dir / "logs"))
                        if Path("reports").exists():
                            shutil.move("reports", str(self.workspace_dir / "reports"))
                        console.print(f"[green]Imported legacy session into {self.workspace_dir}[/green]")
                    except Exception as e:
                        console.print(f"[yellow]Warning: failed to migrate files: {e}[/yellow]")
                else:
                    console.print("[dim]Continuing with legacy session_target.json in CWD.[/dim]")
                    # keep values loaded but do not create workspace
            else:
                # attempt to find any existing engagements and load a default?
                pass
        except Exception as e:
            console.print(f"[dim yellow]Warning: Failed to load session_target.json: {e}[/dim yellow]")
    
    def save(self) -> None:
        """Save target_state to session_target.json."""
        try:
            data = {
                "ip": self.ip,
                "domain": self.domain,
                "ports": self.ports,
                "notes": self.notes,
                "creds": self.creds,
            }
            if self.workspace_dir:
                self.workspace_dir.mkdir(parents=True, exist_ok=True)
                target_file = self.workspace_dir / "target.json"
                with open(target_file, "w") as f:
                    json.dump(data, f, indent=2)
            else:
                with open("session_target.json", "w") as f:
                    json.dump(data, f, indent=2)
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to save target state: {e}[/yellow]")

    def _ensure_workspace(self) -> None:
        """Create and set workspace dir based on current target (ip or domain)."""
        identifier = self.ip or self.domain
        if not identifier:
            return
        name = _sanitize_target(identifier)
        root = _engagements_root()
        ws = root / name
        ws.mkdir(parents=True, exist_ok=True)
        # ensure logs and reports dirs exist
        (ws / "logs").mkdir(exist_ok=True)
        (ws / "reports").mkdir(exist_ok=True)
        self.workspace_dir = ws

    def ensure_workspace_for_set(self) -> Optional[Path]:
        """Ensure workspace exists and return path to new session log (if created)."""
        if not (self.ip or self.domain):
            return None
        if not self.workspace_dir:
            self._ensure_workspace()
        return self.workspace_dir

    def list_engagements(self) -> List[Path]:
        root = _engagements_root()
        return [p for p in root.iterdir() if p.is_dir()]

    def select_engagement(self, name: str) -> bool:
        root = _engagements_root()
        candidate = root / name
        if not candidate.exists():
            return False
        # load target.json if present
        target_file = candidate / "target.json"
        try:
            if target_file.exists():
                with open(target_file, "r") as f:
                    loaded = json.load(f)
                self.ip = loaded.get("ip")
                self.domain = loaded.get("domain")
                self.ports = loaded.get("ports", [])
                self.notes = loaded.get("notes", [])
                self.creds = loaded.get("creds", [])
            self.workspace_dir = candidate
            return True
        except Exception:
            return False
    
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
    
    def __init__(self, target_state: TargetState, current_mode: str = "htb"):
        self.history: List[Dict[str, str]] = []
        self.target_state = target_state
        self.current_mode = current_mode
        self.max_tokens = MAX_HISTORY_TOKENS
    
    def add_message(self, role: str, content: str) -> None:
        """Add a message to conversation history."""
        self.history.append({"role": role, "content": content})
    
    def estimate_tokens(self) -> float:
        """Estimate token count for current history."""
        return sum(len(msg.get("content", "")) / 4 for msg in self.history)
    
    def trim_history(self) -> None:
        """Trim conversation history if it exceeds token limit."""
        current_tokens = self.estimate_tokens()
        
        if current_tokens > self.max_tokens:
            console.print(
                "[dim]Trimming old context to stay within token limit...[/dim]"
            )
            # Protect any system messages and the current target block from removal.
            # Only remove older user/assistant turns that do not contain the
            # '[CURRENT TARGET]' marker. This ensures the system prompt (when
            # represented as a system message) and the running target context
            # remain available to the LLM.
            def is_protected(msg: Dict[str, str]) -> bool:
                if msg.get("role") == "system":
                    return True
                content = msg.get("content", "")
                if "[CURRENT TARGET]" in content:
                    return True
                return False

            # Remove oldest unprotected messages until under token limit.
            while current_tokens > self.max_tokens:
                # find earliest removable index
                removable_index = None
                for idx, m in enumerate(self.history):
                    if not is_protected(m):
                        removable_index = idx
                        break
                # if nothing removable, stop to avoid dropping protected context
                if removable_index is None:
                    console.print("[dim yellow]Cannot trim further without losing protected context.[/dim yellow]")
                    break

                # Prefer removing a user+assistant pair when possible
                # If removable_index points to a user and next is assistant and also removable, drop both.
                if (
                    self.history[removable_index].get("role") == "user"
                    and removable_index + 1 < len(self.history)
                    and not is_protected(self.history[removable_index + 1])
                    and self.history[removable_index + 1].get("role") == "assistant"
                ):
                    # pop twice
                    self.history.pop(removable_index)
                    self.history.pop(removable_index)
                else:
                    # just pop the single removable message
                    self.history.pop(removable_index)

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
