import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

# Example line:
# Jan 12 14:22:31 hostname sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51122 ssh2

# Regex patterns to match different SSH authentication events
FAILED_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)")
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")

@dataclass
class AuthEvent:
    timestamp: datetime
    event_type: str   # "failed" | "accepted" | "invalid_user"
    user: str
    ip: str
    raw: str

def _parse_timestamp(line: str, year: int) -> Optional[datetime]:
    """Extract and parse timestamp from syslog format (e.g., 'Jan 12 14:22:31')"""
    try:
        ts_str = line[:15]  # First 15 characters contain the timestamp
        return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        return None

def parse_auth_log(path: str, year: int = 2026) -> List[AuthEvent]:
    """Parse SSH authentication log file and extract relevant events"""
    events: List[AuthEvent] = []
    
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            
            # Parse timestamp from line
            ts = _parse_timestamp(line, year)
            if not ts:
                continue

            # Check for failed password attempt
            m = FAILED_RE.search(line)
            if m:
                events.append(AuthEvent(ts, "failed", m.group("user"), m.group("ip"), line))
                continue

            # Check for accepted password
            m = ACCEPTED_RE.search(line)
            if m:
                events.append(AuthEvent(ts, "accepted", m.group("user"), m.group("ip"), line))
                continue

            # Check for invalid user attempt
            m = INVALID_USER_RE.search(line)
            if m:
                events.append(AuthEvent(ts, "invalid_user", m.group("user"), m.group("ip"), line))
                continue

    return events