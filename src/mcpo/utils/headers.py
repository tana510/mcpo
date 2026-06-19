import logging
import re
from typing import Dict, List, Optional, Any

import httpx
from fastapi import Request

logger = logging.getLogger(__name__)


def validate_client_header_forwarding_config(server_name: str, config: Dict[str, Any]) -> None:
    """Validate client header forwarding configuration for a server."""
    if not isinstance(config, dict):
        raise ValueError(f"Server '{server_name}' client_header_forwarding must be a dictionary")
    
    enabled = config.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError(f"Server '{server_name}' client_header_forwarding.enabled must be a boolean")
    
    if not enabled:
        return  # No further validation needed if disabled
    
    whitelist = config.get("whitelist", [])
    blacklist = config.get("blacklist", [])
    
    if whitelist and not isinstance(whitelist, list):
        raise ValueError(f"Server '{server_name}' client_header_forwarding.whitelist must be a list")
    
    if blacklist and not isinstance(blacklist, list):
        raise ValueError(f"Server '{server_name}' client_header_forwarding.blacklist must be a list")
    
    debug_headers = config.get("debug_headers", False)
    if not isinstance(debug_headers, bool):
        raise ValueError(f"Server '{server_name}' client_header_forwarding.debug_headers must be a boolean")


def match_header_pattern(header_name: str, patterns: List[str]) -> bool:
    """Check if header name matches any of the given patterns (case-insensitive)."""
    header_lower = header_name.lower()
    for pattern in patterns:
        if pattern == "*":
            return True
        pattern_lower = pattern.lower()
        if pattern_lower.endswith("*"):
            prefix = pattern_lower[:-1]
            if header_lower.startswith(prefix):
                return True
        elif pattern_lower == header_lower:
            return True
    return False


def filter_headers(
    request_headers: Dict[str, str], 
    whitelist: List[str],
    blacklist: List[str],
    debug_headers: bool = False
) -> Dict[str, str]:
    """Filter request headers based on whitelist and blacklist."""
    filtered_headers = {}
    
    for header_name, header_value in request_headers.items():
        # Skip if in blacklist
        if blacklist and match_header_pattern(header_name, blacklist):
            if debug_headers:
                logger.debug(f"Header '{header_name}' blocked by blacklist")
            continue
        
        # Include if in whitelist (or no whitelist specified)
        if not whitelist or match_header_pattern(header_name, whitelist):
            filtered_headers[header_name] = header_value
            if debug_headers:
                logger.debug(f"Header '{header_name}' forwarded")
        elif debug_headers:
            logger.debug(f"Header '{header_name}' not in whitelist")
    
    return filtered_headers


def process_headers_for_server(
    request: Request,
    header_config: Dict[str, Any]
) -> Dict[str, str]:
    """Process and filter headers for a specific MCP server."""
    if not header_config.get("enabled", False):
        return {}
    
    # Convert FastAPI headers to dict
    request_headers = dict(request.headers)
    
    # Get configuration values
    whitelist = header_config.get("whitelist", [])
    blacklist = header_config.get("blacklist", [])
    debug_headers = header_config.get("debug_headers", False)
    
    # Filter headers based on whitelist/blacklist
    filtered_headers = filter_headers(request_headers, whitelist, blacklist, debug_headers)
    
    if debug_headers:
        logger.debug(f"Final forwarded headers: {list(filtered_headers.keys())}")

    return filtered_headers


def create_header_forwarding_client_factory(
    per_request_headers: Dict[str, str],
):
    """Create an httpx client factory that injects per-request forwarded headers
    via event hooks. The factory reads from the provided mutable dict at request
    time, allowing the caller to populate it before each MCP call."""

    def factory(
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[httpx.Timeout] = None,
        auth: Optional[httpx.Auth] = None,
    ) -> httpx.AsyncClient:
        async def inject_forwarded_headers(request: httpx.Request):
            for key, value in per_request_headers.items():
                request.headers[key] = value

        kwargs: Dict[str, Any] = {
            "follow_redirects": True,
            "event_hooks": {"request": [inject_forwarded_headers]},
        }

        if timeout is None:
            kwargs["timeout"] = httpx.Timeout(30.0)
        else:
            kwargs["timeout"] = timeout

        if headers is not None:
            kwargs["headers"] = headers

        if auth is not None:
            kwargs["auth"] = auth

        return httpx.AsyncClient(**kwargs)

    return factory
