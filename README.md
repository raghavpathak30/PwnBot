# PwnBot

PwnBot is a Python CLI chatbot focused on authorized penetration testing workflows (HTB labs, personal labs, and bug bounty programs). It helps with recon, exploitation strategy, privesc paths, and report-ready guidance, and includes optional lightweight web search context for current CVEs/tools/topics.

## What It Does

- Runs an interactive security-focused chat session in your terminal.
- Uses Groq-hosted LLMs with model fallback behavior under rate limits.
- Supports engagement modes: `htb`, `bugbounty`, and `recon`.
- Tracks target context (IP, domain, ports, credentials, notes) across session runs.
- Saves session target state and writes conversation logs.
- Optionally augments prompts with top web search results when trigger phrases/patterns are detected.

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
- `/set ip <value>` - Set target IP.
- `/set domain <value>` - Set target domain.
- `/set port <value>` - Add an open port.
- `/set creds <value>` - Add credentials.
- `/note <text>` - Add a timestamped target note.
- `/save` - Save target state to `session_target.json`.
- `/mode htb|bugbounty|recon` - Change engagement mode.
- `/model` - Show active model and ranked availability.
- `/model set <model_id>` - Switch to a specific available model.
- `/exit` or `/quit` - Save target state and exit.