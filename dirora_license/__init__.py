"""Dirora software-licensing client for Python.

Quick start::

    from dirora_license import Client, Config

    client = Client(Config(
        tenant="your-shop",
        public_key_hex="79b5...",          # Admin > Licences > For developers
        app_version="2.4.0",
        build_date=datetime(2026, 11, 1, tzinfo=timezone.utc),
        cache_path=Path.home() / ".your-app" / "licence.json",
    ))
    client.activate("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
    state = client.check()       # on every start
    if not state.can_run: ...
"""
from .client import (  # noqa: F401
    APIError,
    BadSignature,
    ChecksumMismatch,
    Client,
    Config,
    SignIn,
    SignInDenied,
    SignInExpired,
    State,
    Token,
    key_id,
    verify_token,
)
from .hardware import collect_hardware, machine_fingerprint  # noqa: F401

__all__ = ["APIError", "BadSignature", "ChecksumMismatch", "Client", "Config", "SignIn", "SignInDenied",
           "SignInExpired", "State", "Token", "collect_hardware", "key_id", "machine_fingerprint", "verify_token"]
