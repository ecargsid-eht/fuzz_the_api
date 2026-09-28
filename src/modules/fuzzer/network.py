import ipaddress
import socket
from urllib.parse import urlparse
import httpx
from fastapi import HTTPException

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def private_or_reserved(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in BLOCKED_IP_NETWORKS)
    except ValueError:
        return True

def validate_safe_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https protocols are supported.")
    
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid target host.")

    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for entry in addr_info:
            ip_str = entry[4][0]
            if private_or_reserved(ip_str):
                raise ValueError(f"Host '{hostname}' resolves to private/reserved IP: {ip_str}")
    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {hostname}")

    return url

async def safe_fetch_url(url: str, headers: dict = None, timeout: float = 15.0, max_redirects: int = 3) -> httpx.Response:
    """Fetches URL while validating each redirect destination against SSRF rules."""
    current_url = validate_safe_url(url)
    redirects = 0
    
    async with httpx.AsyncClient(headers=headers or {}) as client:
        while True:
            response = await client.get(current_url, timeout=timeout, follow_redirects=False)
            if response.is_redirect:
                redirects += 1
                if redirects > max_redirects:
                    raise HTTPException(status_code=400, detail="Too many redirects.")
                next_url = response.headers.get("location")
                if not next_url:
                    raise HTTPException(status_code=400, detail="Redirect missing location header.")
                current_url = validate_safe_url(str(httpx.URL(current_url).join(next_url)))
                continue
            return response