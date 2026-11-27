"""Activate a licence (key, sign-in or trial) and check it, the way an app
does on start-up.

    python examples/activate.py your-shop <public-key-hex> [LICENCE-KEY]
    python examples/activate.py your-shop <public-key-hex> --signin <product-id>
    python examples/activate.py your-shop <public-key-hex> --trial <product-id>
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

from dirora_license import APIError, Client, Config

tenant, pubkey, *rest = sys.argv[1:]
product = rest[1] if len(rest) > 1 else ""
client = Client(Config(tenant=tenant, public_key_hex=pubkey, product_id=product, app_version="1.0.0",
                       build_date=datetime(2026, 11, 1, tzinfo=timezone.utc),
                       cache_path=Path.home() / ".example-app" / "licence.json"))
try:
    if rest and rest[0] == "--signin":
        s = client.start_sign_in()
        print(f"Open {s.verification_url} and approve code {s.user_code}")
        client.wait_for_sign_in(s)
    elif rest and rest[0] == "--trial":
        client.start_trial()
    elif rest:
        client.activate(rest[0])
except APIError as e:
    sys.exit(f"failed: {e.code}")
state = client.check()
if not state.can_run:
    sys.exit(f"licence not valid for this build: {state.error}")
t = state.token
print(f"licensed ({t.status}, {t.license_model}, updates until {t.updates_until or 'lifetime'}, online={state.online})")
if t.license_model == "floating":
    client.release()  # free the seat on exit
