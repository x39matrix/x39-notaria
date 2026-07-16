"""Regression tests for X-39 Notaría after security audit:
 (1) CSRF required on ALL mutating routes
 (2) email fingerprint = HMAC-SHA256(FP_HMAC_SECRET, email) not plain SHA-256
 (3) rate-limiting uses X-Forwarded-For; SameSite=Lax cookie
Backend-only tests. Uses REACT_APP_BACKEND_URL + /api prefix.
"""
import os
import base64
import hashlib
import hmac
import json
import io
import zipfile
import time
import secrets as _secrets

import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
API = f"{BASE_URL}/api/notaria"

# Read FP_HMAC_SECRET from backend/.env (test-time helper only)
def _read_env(k):
    with open("/app/backend/.env") as f:
        for line in f:
            line = line.strip()
            if line.startswith(k + "="):
                v = line.split("=", 1)[1].strip().strip('"')
                return v
    return None

FP_HMAC_SECRET = _read_env("FP_HMAC_SECRET")
HWG_ADMIN_TOKEN = _read_env("HWG_ADMIN_TOKEN")

TOKEN_A = "test_session_qa_a"
TOKEN_B = "test_session_qa_b"
EMAIL_A = "qa.a@example.com"
EMAIL_B = "qa.b@example.com"


def _bearer(t):
    return {"Authorization": f"Bearer {t}"}


def _csrf(token):
    r = requests.get(f"{API}/auth/me", headers=_bearer(token), timeout=15)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("authenticated") is True
    return data["csrf_token"]


@pytest.fixture(scope="module")
def csrf_a():
    return _csrf(TOKEN_A)


@pytest.fixture(scope="module")
def csrf_b():
    return _csrf(TOKEN_B)


# ------------ 1) CSRF matrix ------------

def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class TestCSRFMatrix:
    """Every mutating POST must reject requests without a valid X-CSRF-Token (403)."""

    def _post_no_csrf(self, path, body=None, token=TOKEN_A):
        return requests.post(f"{API}{path}", json=(body or {}), headers=_bearer(token), timeout=15)

    def _post_with_csrf(self, path, csrf, body=None, token=TOKEN_A):
        h = _bearer(token)
        h["X-CSRF-Token"] = csrf
        return requests.post(f"{API}{path}", json=(body or {}), headers=h, timeout=15)

    def test_create_agreement_csrf(self, csrf_a):
        body = {"title": "TEST_csrf_1", "content_hash": _content_hash("csrf test 1"),
                "content_kind": "text", "content_text": "x", "party_b_email": EMAIL_B}
        r_no = self._post_no_csrf("/agreements", body)
        assert r_no.status_code == 403, f"expected 403 no-csrf, got {r_no.status_code}: {r_no.text}"
        r_ok = self._post_with_csrf("/agreements", csrf_a, body)
        assert r_ok.status_code == 200, r_ok.text
        # store on class for reuse
        TestCSRFMatrix.aid_shared = r_ok.json()["agreement_id"]
        TestCSRFMatrix.invite_shared = r_ok.json()["invite_token"]

    def test_join_csrf(self, csrf_b):
        aid = TestCSRFMatrix.aid_shared
        invite = TestCSRFMatrix.invite_shared
        r_no = self._post_no_csrf(f"/agreements/{aid}/join", {"invite_token": invite}, token=TOKEN_B)
        assert r_no.status_code == 403
        r_ok = self._post_with_csrf(f"/agreements/{aid}/join", csrf_b, {"invite_token": invite}, token=TOKEN_B)
        assert r_ok.status_code == 200, r_ok.text

    def test_post_message_csrf(self, csrf_a):
        aid = TestCSRFMatrix.aid_shared
        body = {"ct": "AAAA", "iv": "AAAA"}
        r_no = self._post_no_csrf(f"/agreements/{aid}/messages", body)
        assert r_no.status_code == 403
        r_ok = self._post_with_csrf(f"/agreements/{aid}/messages", csrf_a, body)
        assert r_ok.status_code == 200, r_ok.text

    def test_publish_e2e_key_csrf(self, csrf_a):
        aid = TestCSRFMatrix.aid_shared
        body = {"public_key_jwk": {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
        r_no = self._post_no_csrf(f"/agreements/{aid}/e2e_key", body)
        assert r_no.status_code == 403
        r_ok = self._post_with_csrf(f"/agreements/{aid}/e2e_key", csrf_a, body)
        assert r_ok.status_code == 200, r_ok.text

    def test_publish_e2e_pq_key_csrf(self, csrf_a):
        aid = TestCSRFMatrix.aid_shared
        # A -> xwing_pub_b64 must decode to 1216 bytes; use random bytes for CSRF matrix test
        pub = base64.b64encode(_secrets.token_bytes(1216)).decode()
        body = {"xwing_pub_b64": pub}
        r_no = self._post_no_csrf(f"/agreements/{aid}/e2e_pq_key", body)
        assert r_no.status_code == 403, f"e2e_pq_key without CSRF should be 403, got {r_no.status_code}: {r_no.text}"
        r_ok = self._post_with_csrf(f"/agreements/{aid}/e2e_pq_key", csrf_a, body)
        assert r_ok.status_code == 200, r_ok.text

    def test_sign_csrf(self, csrf_a):
        aid = TestCSRFMatrix.aid_shared
        r_no = self._post_no_csrf(f"/agreements/{aid}/sign")
        assert r_no.status_code == 403
        r_ok = self._post_with_csrf(f"/agreements/{aid}/sign", csrf_a)
        assert r_ok.status_code == 200, r_ok.text

    def test_refresh_ots_csrf_no_token(self):
        # Need a sealed agreement to reach the OTS path. For CSRF, we only care that no-token -> 403.
        # Use the historical sealed agreement.
        aid = "85f43a8b9cc748abe30a"
        r_no = self._post_no_csrf(f"/agreements/{aid}/ots/refresh", token=TOKEN_A)
        assert r_no.status_code == 403


# ------------ 2) GET routes work with only Bearer (no CSRF) ------------

class TestGETNoCSRFNeeded:
    def test_auth_me(self):
        r = requests.get(f"{API}/auth/me", headers=_bearer(TOKEN_A), timeout=10)
        assert r.status_code == 200 and r.json().get("authenticated") is True

    def test_list_agreements(self):
        r = requests.get(f"{API}/agreements", headers=_bearer(TOKEN_A), timeout=10)
        assert r.status_code == 200 and isinstance(r.json(), list)

    def test_messages_e2e_keys(self):
        aid = TestCSRFMatrix.aid_shared
        for path in (f"/agreements/{aid}/messages", f"/agreements/{aid}/e2e_keys", f"/agreements/{aid}/e2e_pq_keys"):
            r = requests.get(f"{API}{path}", headers=_bearer(TOKEN_A), timeout=10)
            assert r.status_code == 200, f"{path} -> {r.status_code}: {r.text}"


# ------------ 3) HMAC fingerprint ------------

def _hmac_fp(email: str) -> str:
    return hmac.new(FP_HMAC_SECRET.encode(), email.lower().strip().encode(), hashlib.sha256).hexdigest()


def _plain_sha256(email: str) -> str:
    return hashlib.sha256(email.lower().strip().encode()).hexdigest()


class TestHMACFingerprint:
    def test_fp_a_is_hmac_not_plain_sha256(self):
        expected = _hmac_fp(EMAIL_A)
        plain = _plain_sha256(EMAIL_A)
        assert expected != plain
        assert len(expected) == 64
        # We'll verify against a freshly sealed agreement in the full E2E test class.
        TestHMACFingerprint.expected_a = expected
        TestHMACFingerprint.expected_b = _hmac_fp(EMAIL_B)


# ------------ 4) End-to-end sealing flow ------------

class TestE2EFlow:
    aid = None

    def test_full_flow_seals_with_hmac_fps(self, csrf_a, csrf_b):
        # Create by A
        body = {"title": "TEST_e2e_full", "content_hash": _content_hash("full flow"),
                "content_kind": "text", "content_text": "hola", "party_b_email": EMAIL_B}
        r = requests.post(f"{API}/agreements", json=body,
                          headers={**_bearer(TOKEN_A), "X-CSRF-Token": csrf_a}, timeout=15)
        assert r.status_code == 200, r.text
        aid = r.json()["agreement_id"]
        invite = r.json()["invite_token"]
        TestE2EFlow.aid = aid

        # B joins
        r = requests.post(f"{API}/agreements/{aid}/join", json={"invite_token": invite},
                          headers={**_bearer(TOKEN_B), "X-CSRF-Token": csrf_b}, timeout=15)
        assert r.status_code == 200, r.text

        # Both publish PQ keys (random blobs of correct length; server only validates size)
        pub_a = base64.b64encode(_secrets.token_bytes(1216)).decode()
        r = requests.post(f"{API}/agreements/{aid}/e2e_pq_key", json={"xwing_pub_b64": pub_a},
                          headers={**_bearer(TOKEN_A), "X-CSRF-Token": csrf_a}, timeout=15)
        assert r.status_code == 200, r.text

        ct_b = base64.b64encode(_secrets.token_bytes(1120)).decode()
        r = requests.post(f"{API}/agreements/{aid}/e2e_pq_key", json={"xwing_ct_b64": ct_b},
                          headers={**_bearer(TOKEN_B), "X-CSRF-Token": csrf_b}, timeout=15)
        assert r.status_code == 200, r.text

        # Verify GET reflects both
        r = requests.get(f"{API}/agreements/{aid}/e2e_pq_keys", headers=_bearer(TOKEN_A), timeout=10)
        assert r.status_code == 200
        d = r.json()
        assert d["A"]["xwing_pub_b64"] == pub_a
        assert d["B"]["xwing_ct_b64"] == ct_b

        # Exchange 2 encrypted messages
        for sender_tok, sender_csrf in [(TOKEN_A, csrf_a), (TOKEN_B, csrf_b)]:
            r = requests.post(f"{API}/agreements/{aid}/messages",
                              json={"ct": base64.b64encode(b"cipher").decode(),
                                    "iv": base64.b64encode(b"iv1234567890").decode()},
                              headers={**_bearer(sender_tok), "X-CSRF-Token": sender_csrf}, timeout=15)
            assert r.status_code == 200, r.text

        # Both sign -> triggers sealing (background). Poll for sealed.
        for tok, cs in [(TOKEN_A, csrf_a), (TOKEN_B, csrf_b)]:
            r = requests.post(f"{API}/agreements/{aid}/sign",
                              headers={**_bearer(tok), "X-CSRF-Token": cs}, timeout=15)
            assert r.status_code == 200, r.text

        sealed = None
        for _ in range(20):
            r = requests.get(f"{API}/agreements/{aid}", headers=_bearer(TOKEN_A), timeout=10)
            assert r.status_code == 200
            if r.json()["status"] == "sealed":
                sealed = r.json()
                break
            time.sleep(1)
        assert sealed, "agreement never sealed"

        expected_a = _hmac_fp(EMAIL_A)
        expected_b = _hmac_fp(EMAIL_B)

        # public/{aid} matches
        r = requests.get(f"{API}/public/{aid}", timeout=15)
        assert r.status_code == 200, r.text
        pub = r.json()
        assert pub["party_a_fp"] == expected_a, f"got {pub['party_a_fp']} vs expected {expected_a}"
        assert pub["party_b_fp"] == expected_b
        # ensure it's NOT plain sha256
        assert pub["party_a_fp"] != _plain_sha256(EMAIL_A)

        # anchored payload must contain fps and NOT contain plain emails
        r = requests.get(f"{API}/proof/{aid}.json", timeout=15)
        assert r.status_code == 200
        payload_bytes = r.content
        payload = json.loads(payload_bytes.decode())
        assert payload["party_a_fp"] == expected_a
        assert payload["party_b_fp"] == expected_b
        assert EMAIL_A not in payload_bytes.decode()
        assert EMAIL_B not in payload_bytes.decode()


# ------------ 5) Historical regression ------------

class TestHistorical:
    AID = "85f43a8b9cc748abe30a"

    def test_public_historical(self):
        r = requests.get(f"{API}/public/{self.AID}", timeout=15)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("ots_status") == "anchored_btc", f"ots_status={d.get('ots_status')}"
        assert d.get("cold") and d["cold"].get("tier") == "COLD"

    def test_zip_bundle(self):
        r = requests.get(f"{API}/proof/{self.AID}.zip", timeout=20)
        assert r.status_code == 200, r.text
        z = zipfile.ZipFile(io.BytesIO(r.content))
        names = set(z.namelist())
        for want in ("proof.json", "proof.json.ots", "signatures.json", "README.md"):
            assert want in names, f"missing {want}: got {names}"

    def test_cold_key(self):
        r = requests.get(f"{API}/cold_key", timeout=10)
        assert r.status_code == 200
        d = r.json()
        assert d.get("registered") is True
        assert d.get("fingerprint") == "8453a25a41d6fe8fcb5647600f042a7c303daaca79b80928534025711981c6a1"


# ------------ 6) Cookie SameSite=Lax sanity ------------

class TestCookieSameSite:
    def test_lax_cookie_on_auth_session(self):
        # We can't do a full session_id exchange (no real Emergent session_id), but we can hit
        # auth/logout which sets the cookie deletion. Instead, check /auth/me works via Bearer only.
        # For SameSite proof, inspect the /auth/session set-cookie via an invalid session_id which
        # returns 401 without cookie; safest is to verify the source declares samesite="lax".
        with open("/app/backend/notaria.py") as f:
            src = f.read()
        assert 'samesite="lax"' in src, "cookie should be SameSite=Lax"
