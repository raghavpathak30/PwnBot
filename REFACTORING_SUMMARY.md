# PwnBot Refactoring: Package Restructuring

## Summary

PwnBot has been restructured from a single 1,176-line flat file (`PwnBot.py`) into a well-organized package with clear separation of concerns. **All behavior is preserved exactly** — this is pure refactoring, no functionality changes.

## New Structure

```
PwnBot/
├── pwnbot/
│   ├── __init__.py          # Package metadata
│   ├── config.py            # Constants: BASE_PROMPT, MODE_REMINDERS, MODEL_PRIORITY
│   ├── state.py             # TargetState, ConversationManager classes
│   ├── llm.py               # Groq API: init, fetch_available_models, select_model, call_groq_api
│   ├── search.py            # Web search: search_web, should_trigger_search, extract_search_query
│   ├── reporting.py         # Logging: initialize_logging, log_exchange, generate_report
│   ├── parsers.py           # Tool parsing: parse_nmap, parse_gobuster, parse_ffuf, suggest_exploits
│   ├── recon.py             # Execution: handle_run, handle_shell, run_auto_recon
│   ├── commands.py          # Command dispatch: handle_command (all /... commands)
│   └── cli.py               # Main loop: print_banner, main()
├── pwnbot.py                # Entry point (thin wrapper)
├── PwnBot.py                # Original file (preserved for reference)
├── requirements.txt
├── session_target.json
└── logs/
```

## Key Changes

### 1. Mutable State Management

**Before**: Module-level globals
```python
conversation_history: List[Dict[str, str]] = []
target_state: Dict[str, Any] = {...}
current_mode: str = "htb"
active_model: str = ""
available_models: List[str] = []
session_log_path: Optional[Path] = None
groq_client: Optional[Groq] = None
```

**After**: Explicit class instances passed to functions
```python
# In cli.py main():
target_state = TargetState()  # Encapsulates ip, domain, ports, creds, notes + load/save
conversation_manager = ConversationManager(target_state, "htb")  # Handles history + system prompt
session_log_path = initialize_logging()  # Returned, not global
groq_client = init_groq_client()  # Returned, not global
active_model, available_models = select_model(...)  # Parameters passed, not read from globals
```

### 2. State Classes

#### TargetState (state.py)
- **Fields**: `ip`, `domain`, `ports`, `creds`, `notes`
- **Methods**: `load()`, `save()`, `to_dict()`
- **Behavior**: Identical to original—persists to/from `session_target.json`

#### ConversationManager (state.py)
- **Holds**: conversation history, current_mode, reference to target_state
- **Methods**:
  - `add_message(role, content)` — adds to history
  - `estimate_tokens()` — estimates token count
  - `trim_history()` — keeps history ≤ 5000 tokens
  - `build_system_prompt()` — constructs BASE_PROMPT + mode + target context
  - `clear()` — clears history for `/clear` command

### 3. Module Organization

| Module | Responsibility | Notable Functions |
|--------|---|---|
| **config.py** | Constants only | BASE_PROMPT, MODE_REMINDERS, MODEL_PRIORITY |
| **state.py** | State classes | TargetState, ConversationManager |
| **llm.py** | Groq API + failover | `init_groq_client()`, `fetch_available_models()`, `select_model()`, `call_groq_api()` |
| **search.py** | Web search | `search_web()`, `should_trigger_search()`, `extract_search_query()` |
| **reporting.py** | Logging & reports | `initialize_logging()`, `log_exchange()`, `generate_report()` |
| **parsers.py** | Tool output analysis | `parse_nmap_output()`, `parse_gobuster_output()`, `parse_ffuf_output()`, `suggest_exploits()` |
| **recon.py** | Command execution | `handle_run()`, `handle_shell()`, `run_auto_recon()` |
| **commands.py** | Slash-command dispatch | `handle_command()` + all `/command` handlers |
| **cli.py** | Application loop | `main()`, `print_banner()` |
| **pwnbot.py** | Entry point | Imports and calls `main()` |

## Behavioral Equivalence

### Critical Subsystems Preserved

✅ **Groq API failover** — Same logic, returns updated active_model & available_models  
✅ **Token trimming** — Identical algorithm, keeps first message and removes oldest pairs  
✅ **Target persistence** — Same JSON file format and load/save logic  
✅ **Session logging** — Same format, same log directory, same per-exchange logging  
✅ **Web search triggering** — Same patterns (CVE, version, phrases)  
✅ **Tool parsing** — Identical regex and extraction logic for nmap/gobuster/ffuf  
✅ **Exploit suggestions** — Same searchsploit integration with `shell=False`  
✅ **Command handlers** — Every `/command` preserves exact behavior, returns state changes  
✅ **Subprocess safety** — `shlex.split()` + `shell=False` on ALL subprocess calls (except documented interactive `/shell`)  
✅ **Readline history** — Same file location (`~/.pwnbot_history`), same length limit  

### Function Signatures

Original functions that accepted no parameters now receive state objects:

```python
# Before
def handle_command(command: str) -> bool
def call_groq_api(api_message, history_message=None) -> Optional[str]
def run_auto_recon(ip: str) -> None

# After
def handle_command(command, target_state, conversation_manager, groq_client, 
                   active_model, available_models, session_log_path) 
                   -> Tuple[bool, str, list]
def call_groq_api(api_message, conversation_manager, groq_client, 
                  active_model, available_models, history_message=None) 
                  -> Tuple[Optional[str], str, list]
def run_auto_recon(ip, target_state, conversation_manager, groq_client, 
                   active_model, available_models, session_log_path) 
                   -> Tuple[str, list]
```

All return values include updated model state to handle failover.

## Testing Checklist

- [x] Package imports successfully (`python3 -c "from pwnbot.cli import main"`)
- [x] All subprocess calls use `shlex.split` + `shell=False` (verified grep)
- [x] TargetState.load/save preserve JSON format
- [x] ConversationManager token trimming matches original algorithm
- [x] Tool parsers extract same patterns
- [x] Entry point `pwnbot.py` is executable

## Usage

```bash
# Still the same entry point
python3 pwnbot.py

# Or directly via package
python3 -m pwnbot.cli
```

## Next Phases

This refactoring enables future work:
- Phase 2: Improve parsing (e.g., structured nmap JSON parsing instead of regex)
- Phase 3: Add new LLM providers (decouple Groq-specific logic)
- Phase 4: Add plugin system (external tool integrations)
- Phase 5: Add testing suite (classes now testable in isolation)

## No Breaking Changes

- ✅ All slash commands work identically
- ✅ Target persistence format unchanged
- ✅ Session logs format unchanged
- ✅ Readline history file location unchanged
- ✅ Configuration constants available to all modules
- ✅ Secrets still source from environment variables only
