"""
Gmail Integration Module for MailVision.
Provides on-demand Gmail inbox scanning using OAuth 2.0 and the official Gmail REST API.
"""
from gmail.auth import (
    is_configured,
    get_authorization_url,
    exchange_code_for_tokens,
    disconnect_account,
    get_connected_account,
    generate_signed_state,
    validate_signed_state
)
from gmail.service import scan_inbox

__all__ = [
    "is_configured",
    "get_authorization_url",
    "exchange_code_for_tokens",
    "disconnect_account",
    "get_connected_account",
    "generate_signed_state",
    "validate_signed_state",
    "scan_inbox"
]
