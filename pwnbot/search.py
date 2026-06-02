"""
Web search functionality using DuckDuckGo.
"""

import re
from typing import Optional

from duckduckgo_search import DDGS
from rich.console import Console

console = Console(highlight=False)


def search_web(query: str) -> Optional[str]:
    """Perform a web search and return formatted results."""
    try:
        console.print("[yellow]Searching...[/yellow]", end="\r")
        results = DDGS().text(query, max_results=3)
        if not results:
            return None
        
        search_block = "[WEB SEARCH RESULTS]\n"
        for i, result in enumerate(results, 1):
            title = result.get("title", "")
            body = result.get("body", "")
            href = result.get("href", "")
            search_block += f"{i}. {title} — {body} (source: {href})\n"
        search_block += "---\n"
        return search_block
    except Exception as e:
        return None


def should_trigger_search(message: str) -> bool:
    """Check if message should trigger a web search."""
    message_lower = message.lower()
    
    # Check for trigger phrases
    if any(
        phrase in message_lower
        for phrase in ["search for", "look up"]
    ):
        return True
    
    # Check for CVE pattern (CVE-YYYY-NNNN)
    if re.search(r"cve-\d{4}-\d+", message_lower, re.IGNORECASE):
        return True
    
    # Check for version pattern (v1.2.3 only, not bare IPs)
    if re.search(r"v\d+\.\d+\.\d+", message):
        return True
    
    return False


def extract_search_query(message: str) -> str:
    """Extract a clean search query from the message."""
    message_lower = message.lower()
    
    # Try to extract from trigger phrases
    for phrase in ["search for", "look up"]:
        if phrase in message_lower:
            parts = message.split(phrase, 1)
            if len(parts) > 1:
                query = parts[1].strip().rstrip("?.")
                return " ".join(query.split()[:6])
    
    # Try to extract CVE
    cve_match = re.search(r"cve-\d{4}-\d+", message_lower, re.IGNORECASE)
    if cve_match:
        return cve_match.group(0)
    
    # Try to extract version
    version_match = re.search(r"v\d+\.\d+\.\d+", message)
    if version_match:
        words = message.split()
        for i, word in enumerate(words):
            if version_match.group(0) in word:
                start = max(0, i - 2)
                end = min(len(words), i + 3)
                return " ".join(words[start:end])
    
    return message[:100]
