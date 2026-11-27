import base64
import hashlib
import io
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dirora_license import APIError, BadSignature, ChecksumMismatch, Client, Config, key_id, verify_token
from dirora_license.client import _verify_bytes
from dirora_license.hardware import collect_hardware, looks_virtual

VECTOR = json.loads((Path(__file__).parents[1] / "testdata" / "token-v2.json").read_text())
KEY = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"


class VectorTest(unittest.TestCase):
    def test_server_vector(self):
        pub = bytes.fromhex(VECTOR["public_key_hex"])
        self.assertEqual(key_id(pub), VECTOR["kid"])
        tok = verify_token(pub, VECTOR["response"]["data"])
        self.assertEqual(tok.status, "valid")
        self.assertEqual(tok.license_model, "node_locked")
        fp = tok.machine_fingerprint
        now = datetime(2026, 11, 30, tzinfo=timezone.utc)
        self.assertTrue(tok.can_run(fp, datetime(2027, 1, 1, tzinfo=timezone.utc), now))
        self.assertFalse(tok.can_run(fp, datetime(2027, 8, 1, tzinfo=timezone.utc), now))
        self.assertFalse(tok.can_run("other", None, now))
        m = json.loads(_verify_bytes({VECTOR["kid"]: pub}, VECTOR["update_manifest"]))
        self.assertEqual(m["latest"]["sha256"], hashlib.sha256(b"binary").hexdigest())

    def test_tampered_fails(self):
        pub = bytes.fromhex(VECTOR["public_key_hex"])
        signed = dict(VECTOR["response"]["data"])
        signed["payload"] = base64.b64encode(base64.b64decode(signed["payload"]).replace(b'"valid"', b'"VALID"')).decode()
        with self.assertRaises(BadSignature):
            verify_token(pub, signed)


class FakeAPI:
    def __init__(self):
        self.priv = Ed25519PrivateKey.generate()
        raw = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pub_hex, self.kid = raw.hex(), key_id(raw)
        self.floating = False
        self.approved = False
        self.seats = set()
        self.used = 0
        self.seen = set()
        self.device_fp = ""

    def sign(self, obj):
        p = json.dumps(obj).encode()
        return {"alg": "Ed25519", "kid": self.kid, "payload": base64.b64encode(p).decode(),
                "signature": base64.b64encode(self.priv.sign(p)).decode()}

    def token(self, fp, nonce, auth="key", valid=timedelta(hours=48), **extra):
        now = datetime.now(timezone.utc)
        f = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
        return self.sign({"v": 2, "status": "valid", "machine_fingerprint": fp, "nonce": nonce, "updates_policy": "lifetime",
                          "license_model": "floating" if self.floating else "node_locked", "auth": auth,
                          "issued_at": f(now), "checkin_after": f(now + valid / 2), "valid_until": f(now + valid), **extra})


def handler_for(api: FakeAPI):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, status, obj):
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            b = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            p = self.path
            ok = b.get("license_key") == KEY or b.get("activation_secret") == "secret-1"
            valid = timedelta(minutes=10) if api.floating else timedelta(hours=48)
            if p in ("/activate", "/validate"):
                if not ok:
                    return self.send(404, {"error": "license_not_found"})
                if api.floating:
                    if b["machine_fingerprint"] not in api.seats and len(api.seats) >= 1:
                        return self.send(409, {"error": "no_seat_available"})
                    api.seats.add(b["machine_fingerprint"])
                auth = "user" if b.get("activation_secret") else "key"
                return self.send(200, {"data": api.token(b["machine_fingerprint"], b["nonce"], auth, valid)})
            if p == "/deactivate":
                api.seats.discard(b["machine_fingerprint"])
                return self.send(200, {"data": {}})
            if p == "/trials/start":
                end = (datetime.now(timezone.utc) + timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
                return self.send(200, {"data": {"license_key": "TTTTT-TTTTT-TTTTT-TTTTT-TTTTT",
                                                "token": api.token(b["machine_fingerprint"], b["nonce"], license_type="trial", expires_at=end)}})
            if p == "/device/start":
                api.device_fp = b["machine_fingerprint"]
                return self.send(200, {"data": {"device_code": "dev-1", "user_code": "ABCD-EFGH",
                                                "verification_url": "https://shop/account/device", "expires_in": 900, "interval": 0}})
            if p == "/device/poll":
                if not api.approved:
                    return self.send(200, {"data": {"status": "pending"}})
                return self.send(200, {"data": {"status": "approved", "activation_secret": "secret-1",
                                                "token": api.token(api.device_fp, b["nonce"], "user", valid)}})
            if p == "/usage":
                amount = b["amount"]
                k = b.get("idempotency_key")
                if k and k in api.seen:
                    amount = 0
                if api.used + amount > 3:
                    return self.send(409, {"error": "usage_limit_reached"})
                api.used += amount
                if k:
                    api.seen.add(k)
                return self.send(200, {"data": api.sign({"kind": "usage", "meter": b["meter"], "used": api.used, "limit": 3,
                                                         "remaining": 3 - api.used, "machine_fingerprint": b["machine_fingerprint"],
                                                         "nonce": b["nonce"]})})
            if p == "/updates/check":
                return self.send(200, {"data": {"manifest": api.sign({"kind": "update", "machine_fingerprint": b["machine_fingerprint"],
                    "nonce": b["nonce"], "update_available": True,
                    "latest": {"version": "2.0.0", "file_id": "f-1", "sha256": hashlib.sha256(b"binary").hexdigest()}})}})
            if p == "/releases/download":
                self.send_response(200)
                self.send_header("Content-Length", "6")
                self.end_headers()
                self.wfile.write(b"binary")
                return
            self.send(404, {})
    return H


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.srv = HTTPServer(("127.0.0.1", 0), handler_for(self.api))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._stop()
        self.tmp.cleanup()

    def _stop(self):
        if self.srv is not None:
            self.srv.shutdown()
            self.srv.server_close()
            self.srv = None

    def client(self, fp="fp-1", cache="licence.json", now=None, **kw):
        cfg = Config(tenant="shop", public_key_hex=kw.pop("pub", self.api.pub_hex), fingerprint=fp, product_id="p-1",
                     base_url=f"http://127.0.0.1:{self.port}", cache_path=Path(self.tmp.name) / cache, **kw)
        return Client(cfg, now=now)

    @property
    def port(self):
        return self._port if self.srv is None else self.srv.server_port

    def test_activate_check_offline(self):
        self._port = self.srv.server_port
        c = self.client()
        with self.assertRaises(APIError) as e:
            c.activate("zzzzz-zzzzz-zzzzz-zzzzz-zzzzz")
        self.assertEqual(e.exception.code, "license_not_found")
        c.activate(KEY.lower())
        self.assertTrue(c.check().can_run)
        self._stop()
        later = self.client(now=lambda: datetime.now(timezone.utc) + timedelta(hours=30))
        st = later.check()
        self.assertTrue(st.can_run)
        self.assertFalse(st.online)
        self.assertFalse(self.client(now=lambda: datetime.now(timezone.utc) + timedelta(hours=72)).check().can_run)

    def test_key_rotation(self):
        old = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        both = self.client(pub=old, extra_public_keys_hex=[self.api.pub_hex])
        both.activate(KEY)
        only_old = self.client(pub=old, cache="old.json")
        with self.assertRaises(BadSignature):
            only_old.activate(KEY)

    def test_floating_release(self):
        self.api.floating = True
        a, b = self.client("fp-a", "a.json"), self.client("fp-b", "b.json")
        self.assertEqual(a.activate(KEY).license_model, "floating")
        with self.assertRaises(APIError) as e:
            b.activate(KEY)
        self.assertEqual(e.exception.code, "no_seat_available")
        a.release()
        self.assertTrue(a.license_key)
        b.activate(KEY)

    def test_trial_and_sign_in(self):
        c = self.client()
        tok = c.start_trial("me@example.com")
        self.assertTrue(tok.is_trial)
        self.assertGreaterEqual(tok.trial_days_left(datetime.now(timezone.utc)), 13)
        s = c.start_sign_in()
        self.assertEqual(s.user_code, "ABCD-EFGH")
        self.assertIsNone(c.poll_sign_in(s))
        self.api.approved = True
        tok = c.wait_for_sign_in(s)
        self.assertEqual(tok.auth, "user")
        self.assertTrue(c.signed_in)
        self.assertTrue(c.check().can_run)
        self.assertTrue(self.client().signed_in)

    def test_usage_and_updates(self):
        c = self.client()
        c.activate(KEY)
        self.assertEqual(c.report_usage("exports", 2, "job-1")["used"], 2)
        self.assertEqual(c.report_usage("exports", 2, "job-1")["used"], 2)
        with self.assertRaises(APIError) as e:
            c.report_usage("exports", 2, "job-2")
        self.assertEqual(e.exception.code, "usage_limit_reached")
        m = c.check_for_update()
        self.assertTrue(m["update_available"])
        buf = io.BytesIO()
        c.download(m["latest"], buf)
        self.assertEqual(buf.getvalue(), b"binary")
        with self.assertRaises(ChecksumMismatch):
            c.download({**m["latest"], "sha256": "0" * 64}, io.BytesIO())

    def test_offline_request_and_import(self):
        self._port = self.srv.server_port
        c = self.client("fp-air")
        req = json.loads(base64.b64decode(c.offline_request(KEY)))
        self.assertEqual(req["kind"], "offline_request")
        now = datetime.now(timezone.utc)
        f = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")

        def answer(nonce):
            return json.dumps({"kind": "dirora_offline_licence", "v": 1, "token": self.api.sign({
                "v": 2, "status": "valid", "machine_fingerprint": "fp-air", "nonce": nonce, "offline": True,
                "updates_policy": "lifetime", "issued_at": f(now), "checkin_after": f(now + timedelta(days=365)),
                "valid_until": f(now + timedelta(days=365))})}).encode()

        with self.assertRaises(BadSignature):
            c.import_offline_licence(answer("another"))
        self.assertTrue(c.import_offline_licence(answer(req["nonce"])).offline)
        self._stop()
        st = self.client("fp-air").check()
        self.assertTrue(st.can_run)
        self.assertIsNone(st.error)

    def test_hardware_hashed(self):
        hw = collect_hardware("shop")
        self.assertTrue(all(len(v) == 64 for v in hw.components.values()))
        self.assertTrue(looks_virtual("VMware Virtual Platform"))
        self.assertFalse(looks_virtual("ThinkPad X1"))


if __name__ == "__main__":
    unittest.main()
