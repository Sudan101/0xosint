import socket
import re
from datetime import datetime

def is_valid_domain(domain: str) -> bool:
    """Validate domain format"""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

def resolve_domain(domain: str) -> str | None:
    """Resolve domain to IP address"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def clean_domain(domain: str) -> str:
    """Strip http/https/www from domain input"""
    domain = domain.lower().strip()
    domain = re.sub(r"^https?://", "", domain)
    domain = re.sub(r"^www\.", "", domain)
    domain = domain.rstrip("/")
    return domain

def safe_get(data: dict, *keys, default=None):
    """Safely get nested dict values"""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key, default)
        else:
            return default
    return data
