from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import platform as _platform
import secrets
import socket
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .hardware import HardwareInfo, collect_hardware, machine_fingerprint

DEFAULT_BASE_URL = "https://api.dirora.com/api/licenses/v"

# Stable error codes of the licence API.
INVALID_REQUEST = "invalid_request"
TENANT_NOT_FOUND = "tenant_not_found"
LICENSE_NOT_FOUND = "license_not_found"
KEY_REPLACED = "key_replaced"
LICENSE_BLOCKED = "license_blocked"
ACTIVATION_LIMIT = "activation_limit_reached"
ACTIVATION_CODE_REQUIRED = "activation_code_required"
ACTIVATION_CODE_INVALID = "activation_code_invalid"
MACHINE_NOT_ACTIVATED = "machine_not_activated"
RELEASE_NOT_FOUND = "release_not_found"
UPDATE_NOT_COVERED = "update_not_covered"
FILE_UNAVAILABLE = "file_unavailable"
VIRTUAL_MACHINE = "virtual_machine_not_allowed"
NO_SEAT_AVAILABLE = "no_seat_available"
TRIAL_NOT_AVAILABLE = "trial_not_available"
TRIAL_LIMIT = "trial_limit_reached"
SIGN_IN_REQUIRED = "sign_in_required"
DEVICE_CODE_INVALID = "device_code_invalid"
NO_SEAT = "no_seat"
USAGE_LIMIT = "usage_limit_reached"
METER_NOT_FOUND = "meter_not_found"
RATE_LIMITED = "rate_limited"


class APIError(Exception):
    """A refusal from the licence API; ``code`` is stable, ``message`` English."""

    def __init__(self, status: int, code: str, message: str = ""):
        super().__init__(f"licence API {status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


class BadSignature(Exception):
    """The answer was not signed by your shop's key (or not for this request)."""


class ChecksumMismatch(Exception):
    """A downloaded file does not match the signed SHA-256."""


class SignInDenied(Exception):
    """The person did not allow the machine to sign in."""


class SignInExpired(Exception):
    """The sign-in request expired."""


def key_id(public_key: bytes) -> str:
    """A public key's id: the first 16 hex characters of its SHA-256."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def _parse_time(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class Token:
    """A verified licence answer."""

    v: int = 2
    license_id: str = ""
    product_id: str = ""
    tenant_id: str = ""
    machine_fingerprint: str = ""
    status: str = ""  # valid | lapsed | blocked
    reason: str = ""
    license_type: str = ""  # perpetual | subscription | trial
    expires_at: str = ""
    updates_policy: str = ""
    updates_until: str = ""
    support_policy: str = ""
    support_until: str = ""
    features: List[str] = field(default_factory=list)
    issued_at: str = ""
    checkin_after: str = ""
    valid_until: str = ""
    nonce: str = ""
    license_model: str = ""  # node_locked | floating (a lease)
    auth: str = ""  # key | user
    seats: int = 0
    offline: bool = False

    def has_feature(self, name: str) -> bool:
        return name in (self.features or [])

    @property
    def is_trial(self) -> bool:
        return self.license_type == "trial"

    def trial_days_left(self, now: datetime) -> int:
        end = _parse_time(self.expires_at)
        if not self.is_trial or end is None or now >= end:
            return 0
        return int((end - now).total_seconds() // 86400) + 1

    def covers_build(self, build_date: datetime) -> bool:
        if self.updates_policy != "term":
            return True
        until = _parse_time(self.updates_until)
        return until is not None and build_date <= until

    def can_run(self, fingerprint: str, build_date: Optional[datetime], now: datetime) -> bool:
        """The gate before the software starts working."""
        if self.status == "blocked" or self.machine_fingerprint != fingerprint:
            return False
        valid_until = _parse_time(self.valid_until)
        if valid_until is None or now > valid_until:
            return False
        issued = _parse_time(self.issued_at)
        if issued is not None and now < issued - timedelta(minutes=10):
            return False  # clock set back
        if self.status == "lapsed" or self.updates_policy == "term":
            return build_date is None or self.covers_build(build_date)
        return self.status == "valid"

    def needs_checkin(self, now: datetime) -> bool:
        after = _parse_time(self.checkin_after)
        return after is None or now >= after


def _verify_bytes(keys: Dict[str, bytes], signed: dict) -> bytes:
    try:
        raw = base64.b64decode(signed["payload"], validate=True)
        sig = base64.b64decode(signed["signature"], validate=True)
    except (KeyError, ValueError, binascii.Error):
        raise BadSignature("malformed answer") from None
    kid = signed.get("kid") or ""
    candidates = [keys[kid]] if kid in keys else ([] if kid else list(keys.values()))
    for pub in candidates:
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, raw)
            return raw
        except InvalidSignature:
            continue
    raise BadSignature("signature does not verify")


def _token(raw: bytes) -> Token:
    data = json.loads(raw)
    return Token(**{k: data[k] for k in Token.__dataclass_fields__ if k in data})


def verify_token(public_key: bytes, signed: dict) -> Token:
    """Check a signed answer against one shop key and parse its payload."""
    return _token(_verify_bytes({key_id(public_key): public_key}, signed))


def platform_name() -> str:
    return {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(_platform.system(), "any")


def arch_name() -> str:
    m = _platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x64"
    if m in ("arm64", "aarch64"):
        return "arm64"
    if m in ("i386", "i686", "x86"):
        return "x86"
    return "any"


@dataclass
class Config:
    tenant: str
    public_key_hex: str
    extra_public_keys_hex: List[str] = field(default_factory=list)  # during a key rotation
    product_id: str = ""  # trials and sign-in
    base_url: str = DEFAULT_BASE_URL
    fingerprint: str = ""
    machine_label: str = ""
    app_version: str = ""
    build_date: Optional[datetime] = None
    cache_path: Optional[Path] = None
    send_hardware_info: bool = True
    timeout: float = 30.0


@dataclass
class State:
    token: Optional[Token]
    can_run: bool
    online: bool = False
    error: Optional[Exception] = None


@dataclass
class SignIn:
    device_code: str
    user_code: str
    verification_url: str
    expires_in: int
    interval: int
    started: float = 0.0


class Client:
    """Talks to the licence API for one installation of your product."""

    def __init__(self, config: Config, now=None):
        if not config.tenant:
            raise ValueError("tenant is required")
        self._keys: Dict[str, bytes] = {}
        for h in [config.public_key_hex, *config.extra_public_keys_hex]:
            try:
                pub = bytes.fromhex(h.strip())
            except ValueError:
                pub = b""
            if len(pub) != 32:
                raise ValueError("public keys must be 64 hex characters")
            self._keys[key_id(pub)] = pub
        self.cfg = config
        self.cfg.base_url = config.base_url.rstrip("/")
        if not self.cfg.fingerprint:
            self.cfg.fingerprint = machine_fingerprint(config.tenant)
        if not self.cfg.machine_label:
            self.cfg.machine_label = socket.gethostname()
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._hw: Optional[HardwareInfo] = None
        cached = self._load_cache() or {}
        self.license_key = cached.get("license_key", "")
        self.activation_secret = cached.get("activation_secret", "")

    @property
    def signed_in(self) -> bool:
        return bool(self.activation_secret)

    # ── HTTP ──
    def _post(self, path: str, body: dict):
        req = urllib.request.Request(self.cfg.base_url + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            return urllib.request.urlopen(req, timeout=self.cfg.timeout)
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read() or b"{}")
            except ValueError:
                err = {}
            raise APIError(e.code, err.get("error", ""), err.get("message", "")) from None

    def _post_json(self, path: str, body: dict) -> dict:
        with self._post(path, body) as resp:
            return json.loads(resp.read())["data"]

    def _hardware(self) -> HardwareInfo:
        if not self.cfg.send_hardware_info:
            return HardwareInfo()
        if self._hw is None:
            self._hw = collect_hardware(self.cfg.tenant)
        return self._hw

    def _client_info(self, body: dict, nonce: str = "") -> dict:
        hw = self._hardware()
        body.update({"tenant": self.cfg.tenant, "machine_fingerprint": self.cfg.fingerprint,
                     "machine_label": self.cfg.machine_label, "platform": platform_name(),
                     "app_version": self.cfg.app_version, "components": hw.components, "virtual": hw.virtual})
        if nonce:
            body["nonce"] = nonce
        return body

    def _credential(self, body: dict) -> dict:
        if self.activation_secret:
            body["activation_secret"] = self.activation_secret
        elif self.license_key:
            body["license_key"] = self.license_key
        else:
            raise APIError(0, MACHINE_NOT_ACTIVATED, "no licence activated on this machine")
        return body

    def _accept(self, signed: dict, nonce: str, store: dict) -> Token:
        tok = _token(_verify_bytes(self._keys, signed))
        if tok.nonce != nonce or tok.machine_fingerprint != self.cfg.fingerprint:
            raise BadSignature("answer is not for this request")
        self._save_cache({**store, "token": signed})
        return tok

    def _token_call(self, path: str, body: dict, store: dict) -> Token:
        nonce = secrets.token_hex(12)
        return self._accept(self._post_json(path, self._client_info(body, nonce)), nonce, store)

    # ── API ──
    def verify(self, signed: dict) -> Token:
        return _token(_verify_bytes(self._keys, signed))

    def activate(self, license_key: str, activation_code: str = "") -> Token:
        """Register this machine (or take a floating seat) with a licence key."""
        key = license_key.strip().upper()
        tok = self._token_call("/activate", {"license_key": key, "activation_code": activation_code}, {"license_key": key})
        self.license_key, self.activation_secret = key, ""
        return tok

    def validate(self) -> Token:
        """Check in online (renews a floating seat)."""
        body = self._credential({})
        return self._token_call("/validate", body, {"license_key": self.license_key, "activation_secret": self.activation_secret})

    def release(self) -> None:
        """Free a floating seat when the app closes (the licence stays on the machine)."""
        try:
            body = self._credential({"tenant": self.cfg.tenant, "machine_fingerprint": self.cfg.fingerprint})
        except APIError:
            return
        with self._post("/deactivate", body):
            pass

    def deactivate(self) -> None:
        """Free this machine's place and forget the licence on it."""
        self.release()
        self.license_key = self.activation_secret = ""
        if self.cfg.cache_path:
            try:
                Path(self.cfg.cache_path).unlink()
            except FileNotFoundError:
                pass

    def check(self) -> State:
        """Start-up routine: cached answer while fresh, online when due, cache
        as fallback within the offline grace. Call again before a floating
        lease ends."""
        now = self._now()
        cached = self._cached_token()
        fp, bd = self.cfg.fingerprint, self.cfg.build_date
        if cached and (cached.offline or not cached.needs_checkin(now)):
            return State(cached, cached.can_run(fp, bd, now))
        try:
            tok = self.validate()
            return State(tok, tok.can_run(fp, bd, self._now()), online=True)
        except APIError as e:
            if 0 < e.status < 500 and e.status != 429:
                return State(None, False, error=e)
            err: Exception = e
        except (OSError, BadSignature) as e:
            err = e
        if cached:
            return State(cached, cached.can_run(fp, bd, now), error=err)
        return State(None, False, error=err)

    # ── Trials ──
    def start_trial(self, email: str = "") -> Token:
        """Start (or resume) this machine's free trial of ``Config.product_id``."""
        if not self.cfg.product_id:
            raise ValueError("Config.product_id is required for trials")
        nonce = secrets.token_hex(12)
        data = self._post_json("/trials/start", self._client_info({"product_id": self.cfg.product_id, "email": email}, nonce))
        key = data["license_key"].upper()
        tok = self._accept(data["token"], nonce, {"license_key": key})
        self.license_key, self.activation_secret = key, ""
        return tok

    # ── Sign-in ──
    def start_sign_in(self) -> SignIn:
        """Begin signing this machine in with a customer account: show
        ``user_code`` and ``verification_url``, then ``wait_for_sign_in``."""
        if not self.cfg.product_id:
            raise ValueError("Config.product_id is required for sign-in")
        d = self._post_json("/device/start", self._client_info({"product_id": self.cfg.product_id}))
        return SignIn(d["device_code"], d["user_code"], d["verification_url"], d["expires_in"], d["interval"], time.monotonic())

    def poll_sign_in(self, s: SignIn) -> Optional[Token]:
        """Ask once; None while waiting for approval."""
        nonce = secrets.token_hex(12)
        d = self._post_json("/device/poll", {"tenant": self.cfg.tenant, "device_code": s.device_code, "nonce": nonce})
        status = d.get("status")
        if status == "pending":
            return None
        if status == "denied":
            raise SignInDenied()
        if status == "expired":
            raise SignInExpired()
        tok = self._accept(d["token"], nonce, {"activation_secret": d["activation_secret"]})
        self.license_key, self.activation_secret = "", d["activation_secret"]
        return tok

    def wait_for_sign_in(self, s: SignIn) -> Token:
        while True:
            tok = self.poll_sign_in(s)
            if tok is not None:
                return tok
            if time.monotonic() - s.started > s.expires_in:
                raise SignInExpired()
            time.sleep(max(s.interval, 2))

    # ── Offline ──
    def offline_request(self, license_key: str) -> str:
        """Request text for a machine without internet (save as a .req file)."""
        if not self.cfg.cache_path:
            raise ValueError("Config.cache_path is required for offline activation")
        nonce = secrets.token_hex(12)
        hw = self._hardware()
        req = {"v": 1, "kind": "offline_request", "license_key": license_key.strip().upper(),
               "product_id": self.cfg.product_id, "machine_fingerprint": self.cfg.fingerprint,
               "machine_label": self.cfg.machine_label, "platform": platform_name(), "app_version": self.cfg.app_version,
               "nonce": nonce, "components": hw.components, "virtual": hw.virtual}
        cache = self._load_cache() or {}
        cache["pending_offline_nonce"] = nonce
        self._save_cache(cache)
        return base64.b64encode(json.dumps(req).encode()).decode()

    def import_offline_licence(self, file_content: bytes) -> Token:
        """Check and store the licence file answering this machine's request."""
        try:
            f = json.loads(file_content)
        except ValueError:
            raise ValueError("not a licence file") from None
        if f.get("kind") != "dirora_offline_licence":
            raise ValueError("not a licence file")
        pending = (self._load_cache() or {}).get("pending_offline_nonce")
        if not pending:
            raise ValueError("no offline request is pending on this machine")
        tok = self.verify(f["token"])
        if not tok.offline or tok.nonce != pending or tok.machine_fingerprint != self.cfg.fingerprint:
            raise BadSignature("licence file is not for this request")
        self._save_cache({"token": f["token"]})
        self.license_key = self.activation_secret = ""
        return tok

    # ── Usage ──
    def report_usage(self, meter: str, amount: int = 1, idempotency_key: str = "") -> dict:
        """Count ``amount`` on a usage meter (0 reads it). Over the limit:
        APIError with code ``usage_limit_reached``."""
        nonce = secrets.token_hex(12)
        body = self._credential({"tenant": self.cfg.tenant, "machine_fingerprint": self.cfg.fingerprint,
                                 "meter": meter, "amount": amount, "idempotency_key": idempotency_key, "nonce": nonce})
        u = json.loads(_verify_bytes(self._keys, self._post_json("/usage", body)))
        if u.get("kind") != "usage" or u.get("nonce") != nonce or u.get("machine_fingerprint") != self.cfg.fingerprint:
            raise BadSignature("usage answer is not for this request")
        return u

    # ── Updates ──
    def check_for_update(self, channel: str = "stable") -> dict:
        """The verified update manifest: ``update_available``, ``latest``
        (with ``file_id`` and ``sha256``) and ``newer_blocked``."""
        nonce = secrets.token_hex(12)
        body = self._credential({"tenant": self.cfg.tenant, "machine_fingerprint": self.cfg.fingerprint,
                                 "current_version": self.cfg.app_version, "platform": platform_name(),
                                 "arch": arch_name(), "channel": channel, "nonce": nonce})
        data = self._post_json("/updates/check", body)
        m = json.loads(_verify_bytes(self._keys, data.get("manifest") or {}))
        if m.get("kind") != "update" or m.get("nonce") != nonce or m.get("machine_fingerprint") != self.cfg.fingerprint:
            raise BadSignature("update answer is not for this request")
        return m

    def download(self, release: dict, out: BinaryIO) -> None:
        """Stream ``release`` (from the manifest) into ``out`` and check the signed SHA-256."""
        body = self._credential({"tenant": self.cfg.tenant, "machine_fingerprint": self.cfg.fingerprint,
                                 "file_id": release["file_id"]})
        h = hashlib.sha256()
        with self._post("/releases/download", body) as resp:
            want = (release.get("sha256") or resp.headers.get("X-Checksum-SHA256") or "").lower()
            while chunk := resp.read(1 << 16):
                h.update(chunk)
                out.write(chunk)
        if want and want != h.hexdigest():
            raise ChecksumMismatch(release.get("file_id", ""))

    # ── cache ──
    def _load_cache(self) -> Optional[dict]:
        if not self.cfg.cache_path:
            return None
        try:
            return json.loads(Path(self.cfg.cache_path).read_text())
        except (OSError, ValueError):
            return None

    def _save_cache(self, data: dict) -> None:
        if not self.cfg.cache_path:
            return
        data = {k: v for k, v in data.items() if v}
        path = Path(self.cfg.cache_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)

    def _cached_token(self) -> Optional[Token]:
        c = self._load_cache()
        if not c or "token" not in c:
            return None
        try:
            return self.verify(c["token"])
        except (BadSignature, KeyError, TypeError):
            return None
