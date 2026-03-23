# PwnBot

PwnBot is a Python CLI chatbot focused on authorized penetration testing workflows (HTB labs, personal labs, and bug bounty programs). It helps with recon, exploitation strategy, privesc paths, and report-ready guidance, and includes optional lightweight web search context for current CVEs/tools/topics.

## What It Does

- Interactive terminal chat with streaming AI responses
- Auto model failover across 4 Groq LLMs on rate limits
- `/run <command>` — execute nmap/gobuster/ffuf locally, auto-parse output, get exploit suggestions via searchsploit
- `/shell <command>` — interactive reverse shells, listeners, TTY upgrades
- `/recon` — automated 3-scan nmap recon when target IP is set
- `/paste` — multi-line input for tool output or code
- `/report` — generate markdown pentest report from session data
- `/target` — track IP, domain, ports, creds, notes per session
- Session logs saved to `logs/` as markdown
- Web search auto-triggered on CVE patterns and version strings
- 3 engagement modes: `htb`, `bugbounty`, `recon`

## Commands

| Command | Description |
|---|---|
| `/run <cmd>` | Run local command, parse output, send to AI |
| `/shell <cmd>` | Launch interactive shell or listener |
| `/recon` | Automated nmap reconnaissance |
| `/paste` | Multi-line input (nmap output, code, etc.) |
| `/report` | Generate markdown pentest report |
| `/target` | View/manage target state |
| `/set ip <value>` | Set target IP (prompts for auto recon) |
| `/mode htb\|bugbounty\|recon` | Switch engagement mode |
| `/model` | Show active model and availability |
| `/help` | Show detailed help |

## Requirements

- Python 3.8+
- A Groq API key
- Dependencies listed in `requirements.txt`

## Installation

1. Clone this repository.
2. Move into the project directory.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Export your Groq API key:

```bash
export GROQ_API_KEY="your-api-key"
```

2. Start PwnBot:

```bash
python PwnBot.py
```

## Available Commands

- `/help` - Show help text.
- `/clear` - Clear conversation history (preserves target state and mode).
- `/history` - Show number of user turns currently in memory.
- `/target` - Display the current target state table.
- `/set ip <value>` - Set target IP (prompts for auto recon).
- `/set domain <value>` - Set target domain.
- `/set port <value>` - Add an open port.
- `/set creds <value>` - Add credentials.
- `/note <text>` - Add a timestamped target note.
- `/save` - Save target state to `session_target.json`.
- `/mode htb|bugbounty|recon` - Change engagement mode.
- `/model` - Show active model and ranked availability.
- `/model set <model_id>` - Switch to a specific available model.
- `/paste` - Paste multi-line content (e.g., nmap output, source code) — type `END` on a new line when done. Optionally add a follow-up question.
- `/run <command>` - Execute a shell command locally, capture output, and feed to PWNBOT with optional context. Includes:
  - **Automatic tool parsing** — Detects and parses nmap, gobuster, ffuf output.
  - **Exploit suggestions** — Queries searchsploit for vulnerable services (nmap scans only).
  - **Output truncation** — Limits stdout to 3000 chars and stderr to 1000 chars to prevent token overflow.
  - **Shell construct warnings** — Pipes (`|`), redirects (`>`), and semicolons (`;`) are not supported; use a separate terminal for complex commands.
- `/shell <command>` - Run an interactive command directly in-terminal (listeners, pwncat, PTY upgrades). Use `Ctrl+C` to return to PWNBOT.
- `/recon` - Manually trigger auto recon on the currently-set target IP.
- `/exit` or `/quit` - Save target state and exit.

## Features in Detail

### Auto Recon (`/set ip` or `/recon`)
When you set a target IP with `/set ip <ip>`, PwnBot offers to run automated reconnaissance:
- Runs three **sudo nmap** scans: service detection, full port scan, and UDP scan.
- Truncates output to prevent token overflow.
- Automatically sends results to the LLM for analysis.
- Extracts open ports, services, and OS information.

Note: auto recon requires sudo privileges for nmap in your environment.

### Interactive Shell (`/shell`)
Use `/shell` for commands that need direct terminal interaction (for example netcat listeners or shell upgrades):
- `/shell nc -lvnp 4444`
- `/shell pwncat-cs -lp 4444`
- `/shell python3 -c 'import pty; pty.spawn("/bin/bash")'`

### Tool Output Parsing
PwnBot automatically analyzes output from common penetration testing tools:
- **nmap** — Extracts open ports, services, and OS information.
- **gobuster** — Groups discovered paths by HTTP status code.
- **ffuf** — Groups URLs by HTTP status code.

Parsed insights are displayed in a separate panel before the output is sent to the LLM.

### Exploit Suggestions
For nmap scans, PwnBot queries searchsploit to suggest known exploits:
- Extracts service names and versions from nmap output.
- Queries searchsploit (if installed) with `--no-colour` for clean output.
- Displays the top 5 services found.

Requires `searchsploit` to be installed on your system.

## Security Considerations

- **Command Execution** — PwnBot uses `subprocess.Popen()` with `shell=False` and `shlex.split()` to safely parse commands. This prevents shell injection attacks.
- **Shell Limitations** — Due to the use of `shell=False`, complex shell constructs are not supported:
  - Pipes (`|`) — Use a separate terminal or redirect to a file.
  - Redirects (`>`, `>>`) — Use a separate terminal.
  - Semicolons (`;`) — Chain commands in a separate terminal.
  - PwnBot will warn you if you attempt these.
- **API Keys** — Always set your `GROQ_API_KEY` as an environment variable, never hardcode it.
- **Logs** — Session logs and target state are stored locally in `logs/` and `session_target.json`.

## Tips

- Use `/mode htb`, `/mode bugbounty`, or `/mode recon` to tailor PWNBOT's response style to your engagement type.
- The `/run` command output is automatically parsed for tool-specific insights. Try running `nmap -sV <target>` to see exploit suggestions.
- Use `/shell` when you need an interactive process (listeners, reverse-shell handling, TTY upgrades).
- Multi-line nmap output can be pasted via `/paste` for analysis without sending the raw output to the LLM (useful for context preservation).
- PWNBOT tracks your target context across sessions via `session_target.json` — use `/save` or `/exit` to persist changes.
- Model fallback is automatic under rate limits. Check `/model` to see ranked availability.
- Use arrow keys to navigate command history; history persists in `~/.pwnbot_history`.

## License

Designed for authorized testing only. Respect scope boundaries and obtain written permission before testing.