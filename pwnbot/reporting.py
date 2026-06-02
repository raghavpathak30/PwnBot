"""
Session logging and report generation.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console

from .state import TargetState

console = Console(highlight=False)


def initialize_logging(workspace_dir: Optional[Path] = None) -> Optional[Path]:
    """Initialize session logging and return path to log file.

    If `workspace_dir` is provided, create logs under that workspace; otherwise use CWD/logs.
    """
    try:
        if workspace_dir:
            log_dir = workspace_dir / "logs"
        else:
            log_dir = Path("logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        session_log_path = log_dir / f"session_{timestamp}.md"
        return session_log_path
    except Exception as e:
        console.print(f"[dim yellow]Warning: Could not create logs directory: {e}[/dim yellow]")
        return None


def log_exchange(
    user_msg: str,
    assistant_msg: str,
    session_log_path: Optional[Path],
) -> None:
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


def generate_report(
    target_state: TargetState,
    session_log_path: Optional[Path],
) -> None:
    """Generate and save markdown report from target state."""
    try:
        if target_state.workspace_dir:
            reports_dir = target_state.workspace_dir / "reports"
        else:
            reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        ip_str = target_state.ip or "unknown"
        report_filename = f"report_{ip_str}_{timestamp}.md"
        report_path = reports_dir / report_filename
        
        report_lines = [
            "# Pentest Report",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Target IP:** {target_state.ip or 'not set'}",
            f"**Domain:** {target_state.domain or 'not set'}",
            "",
            "## Open Ports",
        ]
        if target_state.ports:
            for port in target_state.ports:
                report_lines.append(f"- {port}")
        else:
            report_lines.append("- None logged")
        
        report_lines.extend([
            "",
            "## Credentials Found",
        ])
        if target_state.creds:
            for cred in target_state.creds:
                report_lines.append(f"- {cred}")
        else:
            report_lines.append("- None logged")
        
        report_lines.extend([
            "",
            "## Notes",
        ])
        if target_state.notes:
            for note in target_state.notes:
                report_lines.append(f"- {note}")
        else:
            report_lines.append("- None")
        
        report_lines.extend([
            "",
            "## Session Log",
            f"Full session log: {session_log_path if session_log_path else 'No session log available'}",
        ])
        
        report_content = "\n".join(report_lines)
        with open(report_path, "w") as f:
            f.write(report_content)
        
        console.print(f"[green]Report saved to: {report_path}[/green]")
    except Exception as e:
        console.print(f"[bold red]Error generating report: {e}[/bold red]")
