"""X-39 Notaria — prueba de acuerdos anclada en Bitcoin (OpenTimestamps real).

Diseno honesto:
- Los archivos NUNCA se suben: el SHA-256 se calcula en el navegador y solo llega el hash.
- "Anclado en Bitcoin" se muestra SOLO cuando OpenTimestamps confirma (ots info -> BitcoinBlockHeaderAttestation).
- El chat se etiqueta "privado y con acceso restringido" (el servidor guarda el texto; solo A y B leen).
- Firma post-cuantica ML-DSA-87 sobre la prueba (clave publica expuesta, mejor esfuerzo).
"""
import os
import io
import re
import time
import json
import asyncio
import hashlib
import hmac
import secrets
import base64
import zipfile
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation
from typing import Optional

import requests
from fastapi import APIRouter, HTTPException, Depends, Request, Response, Header, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from pymongo import MongoClient
from pqcrypto.sign import ml_dsa_87 as _mldsa

from hwg.crypto import ots_stamp, ots_info_probe, ots_upgrade

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ.get("DB_NAME", "x39matrix")

_client = MongoClient(MONGO_URL)
_db = _client[DB_NAME]
nu = _db["notaria_users"]
na = _db["notaria_agreements"]
nmsg = _db["notaria_messages"]
nmeta = _db["notaria_meta"]
ns = _db["notaria_sessions"]

nu.create_index("email", unique=True)
na.create_index("agreement_id", unique=True)
nmsg.create_index("agreement_id")
ns.create_index("session_token", unique=True)

notaria_router = APIRouter(prefix="/notaria", tags=["notaria"])

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE = re.compile(r"[\x00-\x1f<>]")  # control chars + angle brackets


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(s: str, maxlen: int = 200) -> str:
    if not isinstance(s, str):
        return ""
    s = SAFE.sub("", s).strip()
    if ".." in s or "/" in s or "\\" in s:
        s = s.replace("..", "").replace("/", "").replace("\\", "")
    return s[:maxlen]


_FP_SECRET = os.environ["FP_HMAC_SECRET"].encode()


def _email_fp(email: Optional[str]) -> Optional[str]:
    """Huella HMAC-SHA256 del email (identidad verificable sin exponer el email;
    el secreto de servidor impide confirmar emails adivinados desde la huella publica)."""
    if not email:
        return None
    return hmac.new(_FP_SECRET, email.lower().strip().encode(), hashlib.sha256).hexdigest()


def _fp_a(a: dict) -> Optional[str]:
    return (a.get("proof") or {}).get("party_a_fp") or _email_fp(a["party_a"])


def _fp_b(a: dict) -> Optional[str]:
    return (a.get("proof") or {}).get("party_b_fp") or _email_fp(a.get("party_b"))


# ---------- Validacion de direccion Bitcoin (bech32/bech32m + base58check) ----------
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _bech32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_verify(hrp, data, spec):
    exp = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    const = 1 if spec == "bech32" else 0x2bc830a3
    return _bech32_polymod(exp + data) == const


def _b58check_valid(a: str) -> bool:
    try:
        num = 0
        for ch in a:
            if ch not in _B58:
                return False
            num = num * 58 + _B58.index(ch)
        pad = len(a) - len(a.lstrip("1"))
        body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
        raw = b"\x00" * pad + body
        if len(raw) != 25:
            return False
        chk = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]
        return chk == raw[-4:] and raw[0] in (0x00, 0x05)
    except Exception:
        return False


def _valid_btc_address(addr: str) -> bool:
    if not isinstance(addr, str):
        return False
    a = addr.strip()
    if a.lower().startswith("bc1"):
        a = a.lower()
        try:
            hrp, data = a.rsplit("1", 1)
            dec = [_BECH32.find(c) for c in data]
            if any(d == -1 for d in dec) or len(data) < 6:
                return False
            spec = "bech32" if dec[0] == 0 else "bech32m"
            return hrp == "bc" and _bech32_verify(hrp, dec, spec)
        except Exception:
            return False
    if a[:1] in ("1", "3"):
        return _b58check_valid(a)
    return False


def _btc_to_sats(amount_str: str) -> Optional[int]:
    try:
        return int((Decimal(amount_str) * Decimal(100_000_000)).to_integral_value())
    except (InvalidOperation, ValueError):
        return None


# ---------- Rate limiting (in-memory sliding window per IP+scope) ----------
_hits: dict = {}


def _rate_limit(request: Request, scope: str, limit: int, window: int = 60):
    xff = request.headers.get("X-Forwarded-For", "")
    ip = xff.split(",")[0].strip() if xff else (request.client.host if request.client else "anon")
    key = f"{ip}:{scope}"
    now = time.time()
    if len(_hits) > 10000:
        for k in [k for k, v in _hits.items() if not v or now - v[-1] > 300]:
            _hits.pop(k, None)
    bucket = [t for t in _hits.get(key, []) if now - t < window]
    if len(bucket) >= limit:
        raise HTTPException(429, "Demasiadas solicitudes. Espera un momento.")
    bucket.append(now)
    _hits[key] = bucket


# SEC-003 (2026-07-16): clave WARM de operador RETIRADA. La sk fue eliminada de Mongo.
# Las firmas WARM historicas siguen verificables (pk embebida en cada acuerdo).
# La autoria post-cuantica de acuerdos nuevos la aporta SOLO la co-firma COLD air-gapped.

# ---------- COLD key (air-gapped Pi 5 · ML-DSA-87) — solo verificacion, la sk NUNCA toca el server ----------
def _require_admin(x_admin_token: str):
    tok = os.environ.get("HWG_ADMIN_TOKEN", "")
    if not tok or not x_admin_token or not secrets.compare_digest(x_admin_token, tok):
        raise HTTPException(403, "Token de operador invalido")


def _cold_pubkey():
    """Devuelve (pk_bytes, pk_b64, fingerprint) de la clave COLD soberana registrada, o None."""
    doc = nmeta.find_one({"_id": "cold_mldsa_pub"})
    if not doc:
        return None
    pk_b64 = doc["pk"]
    return base64.b64decode(pk_b64), pk_b64, doc["fingerprint"]


class ColdKeyModel(BaseModel):
    public_key_b64: str


class ColdSigModel(BaseModel):
    signature_b64: str


# ---------- Auth (Emergent-managed Google OAuth) ----------
SESSION_API = "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data"


def _get_or_create_user(email: str, name: Optional[str], picture: Optional[str]) -> dict:
    u = nu.find_one({"email": email}, {"_id": 0})
    if u:
        upd = {}
        if name and u.get("name") != name:
            upd["name"] = name
        if picture and u.get("picture") != picture:
            upd["picture"] = picture
        if "user_id" not in u:
            upd["user_id"] = f"user_{secrets.token_hex(6)}"
        if upd:
            nu.update_one({"email": email}, {"$set": upd})
            u.update(upd)
        return u
    user = {"user_id": f"user_{secrets.token_hex(6)}", "email": email,
            "name": name or "", "picture": picture or "", "created_at": _now()}
    nu.insert_one({**user})
    return user


def _resolve_session(request: Request) -> dict:
    token = request.cookies.get("session_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "No autenticado")
    sess = ns.find_one({"session_token": token}, {"_id": 0})
    if not sess:
        raise HTTPException(401, "Sesion invalida")
    expires_at = sess["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(401, "Sesion expirada")
    return sess


def current_user(request: Request) -> str:
    return _resolve_session(request)["email"]


def require_csrf(request: Request) -> str:
    """Auth + defensa CSRF: exige cabecera X-CSRF-Token igual al token de la sesion.
    Un <form> cross-site no puede establecer cabeceras custom; bloquea la firma forjada."""
    sess = _resolve_session(request)
    header = request.headers.get("X-CSRF-Token", "")
    expected = sess.get("csrf_token") or ""
    if not expected or not header or not secrets.compare_digest(header, expected):
        raise HTTPException(403, "Token CSRF invalido o ausente")
    return sess["email"]


class SessionExchangeModel(BaseModel):
    session_id: str


@notaria_router.post("/auth/session")
async def auth_session(data: SessionExchangeModel, request: Request, response: Response):
    _rate_limit(request, "auth", limit=10, window=60)
    try:
        r = requests.get(SESSION_API, headers={"X-Session-ID": data.session_id}, timeout=15)
    except requests.RequestException:
        raise HTTPException(502, "Servicio de autenticacion no disponible")
    if r.status_code != 200:
        raise HTTPException(401, "session_id invalido o expirado")
    d = r.json()
    email = (d.get("email") or "").lower().strip()
    session_token = d.get("session_token")
    if not email or not session_token:
        raise HTTPException(401, "Identidad incompleta")
    user = _get_or_create_user(email, d.get("name"), d.get("picture"))
    csrf = secrets.token_urlsafe(32)
    ns.update_one(
        {"session_token": session_token},
        {"$set": {"session_token": session_token, "email": email, "user_id": user["user_id"],
                  "csrf_token": csrf,
                  "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
                  "created_at": _now()}},
        upsert=True,
    )
    response.set_cookie("session_token", session_token, max_age=7 * 24 * 3600,
                        httponly=True, secure=True, samesite="lax", path="/")
    return {"email": email, "name": user.get("name", ""), "picture": user.get("picture", ""), "csrf_token": csrf}


@notaria_router.get("/auth/me")
async def auth_me(request: Request):
    # 200 + authenticated:false en vez de 401: evita ruido en consola en rutas publicas
    try:
        sess = _resolve_session(request)
    except HTTPException:
        return {"authenticated": False}
    email = sess["email"]
    csrf = sess.get("csrf_token")
    if not csrf:
        csrf = secrets.token_urlsafe(32)
        ns.update_one({"session_token": sess["session_token"]}, {"$set": {"csrf_token": csrf}})
    u = nu.find_one({"email": email}, {"_id": 0}) or {}
    return {"authenticated": True, "email": email, "name": u.get("name", ""), "picture": u.get("picture", ""), "csrf_token": csrf}


@notaria_router.post("/auth/logout")
async def auth_logout(request: Request, response: Response):
    token = request.cookies.get("session_token")
    if token:
        ns.delete_one({"session_token": token})
    response.delete_cookie("session_token", path="/")
    return {"ok": True}


# ---------- Agreements ----------
class CreateAgreementModel(BaseModel):
    title: str
    content_hash: str
    content_kind: str = "text"          # 'text' | 'file'
    content_text: Optional[str] = None  # solo para kind='text'
    file_name: Optional[str] = None     # metadato para kind='file'
    party_b_email: Optional[str] = None
    pay_amount: Optional[str] = None    # pago no custodial: monto en BTC (decimal string)
    pay_address: Optional[str] = None   # direccion Bitcoin de cobro (de la parte que cobra)
    pay_payer: Optional[str] = None     # 'A' | 'B' — quien paga


def _user_name(email: Optional[str]) -> Optional[str]:
    if not email:
        return None
    u = nu.find_one({"email": email}, {"_id": 0, "name": 1})
    return (u or {}).get("name") or None


def _public_view(a: dict, email: Optional[str] = None) -> dict:
    out = {
        "agreement_id": a["agreement_id"],
        "title": a["title"],
        "content_kind": a["content_kind"],
        "content_text": a.get("content_text") if a["content_kind"] == "text" else None,
        "file_name": a.get("file_name"),
        "content_hash": a["content_hash"],
        "payment": a.get("payment"),
        "party_a": a["party_a"],
        "party_b": a.get("party_b"),
        "party_a_name": _user_name(a["party_a"]),
        "party_b_name": _user_name(a.get("party_b")),
        "status": a["status"],
        "signatures": a.get("signatures", {}),
        "created_at": a["created_at"],
        "sealed_at": a.get("sealed_at"),
        "proof": a.get("proof"),
        "ots": {k: a["ots"].get(k) for k in ("status", "btc_block", "calendars", "stamped_at")} if a.get("ots") else None,
        "pq": {"algorithm": "ML-DSA-87", "signature_b64": a["pq"].get("signature_b64"), "public_key_b64": a["pq"]["public_key_b64"]} if a.get("pq") else None,
        "cold": a.get("cold"),
        "my_role": ("A" if email == a["party_a"] else "B" if email == a.get("party_b") else None),
    }
    if email == a["party_a"] and a["status"] != "sealed":
        out["invite_token"] = a.get("invite_token")
    return out


@notaria_router.post("/agreements")
async def create_agreement(data: CreateAgreementModel, request: Request, email: str = Depends(require_csrf)):
    _rate_limit(request, "create", limit=20, window=60)
    ch = data.content_hash.lower().strip()
    if not HEX64.match(ch):
        raise HTTPException(400, "content_hash debe ser SHA-256 (64 hex)")
    if data.content_kind not in ("text", "file"):
        raise HTTPException(400, "content_kind invalido")
    payment = None
    if data.pay_amount or data.pay_address or data.pay_payer:
        amt = (data.pay_amount or "").strip()
        if not re.match(r"^\d+(\.\d{1,8})?$", amt) or Decimal(amt) <= 0:
            raise HTTPException(400, "Monto de pago invalido (BTC, hasta 8 decimales)")
        addr = (data.pay_address or "").strip()
        if not _valid_btc_address(addr):
            raise HTTPException(400, "Direccion Bitcoin no valida")
        if data.pay_payer not in ("A", "B"):
            raise HTTPException(400, "pay_payer debe ser A o B")
        payment = {"currency": "BTC", "amount": amt, "sats": _btc_to_sats(amt),
                   "address": addr, "payer": data.pay_payer}
    aid = secrets.token_hex(10)
    doc = {
        "agreement_id": aid,
        "title": _clean(data.title, 160) or "Acuerdo sin titulo",
        "content_kind": data.content_kind,
        "content_text": (data.content_text or "")[:20000] if data.content_kind == "text" else None,
        "file_name": _clean(data.file_name or "", 160) if data.content_kind == "file" else None,
        "content_hash": ch,
        "party_a": email,
        "party_b": (data.party_b_email or "").lower().strip() or None,
        "payment": payment,
        "invite_token": secrets.token_urlsafe(18),
        "status": "pending_signatures",
        "signatures": {},
        "created_at": _now(),
    }
    na.insert_one({**doc})
    return _public_view(doc, email)


@notaria_router.get("/agreements")
async def list_agreements(email: str = Depends(current_user)):
    rows = list(na.find({"$or": [{"party_a": email}, {"party_b": email}]}, {"_id": 0}).sort("created_at", -1).limit(200))
    return [_public_view(a, email) for a in rows]


def _member(a: dict, email: str) -> bool:
    return email == a["party_a"] or email == a.get("party_b")


@notaria_router.get("/agreements/{aid}")
async def get_agreement(aid: str, email: str = Depends(current_user)):
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Acuerdo no encontrado")
    if not _member(a, email):
        raise HTTPException(403, "No participas en este acuerdo")
    return _public_view(a, email)


class JoinModel(BaseModel):
    invite_token: str


@notaria_router.post("/agreements/{aid}/join")
async def join_agreement(aid: str, data: JoinModel, email: str = Depends(require_csrf)):
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Acuerdo no encontrado")
    if not secrets.compare_digest(a.get("invite_token", ""), data.invite_token):
        raise HTTPException(403, "Invitacion invalida")
    if _member(a, email):
        return _public_view(a, email)
    if a.get("party_b") and a["party_b"] != email:
        raise HTTPException(409, "Este acuerdo ya tiene una parte B")
    na.update_one({"agreement_id": aid}, {"$set": {"party_b": email}})
    a["party_b"] = email
    return _public_view(a, email)


# ---------- Chat E2E (cifrado extremo-a-extremo, el server solo ve ciphertext) ----------
# Intercambio de claves ECDH P-256 en el navegador; AES-256-GCM por mensaje.
# La clave privada NUNCA toca el server: aqui solo se guardan pubkeys y {ct,iv}.
class MessageModel(BaseModel):
    ct: str
    iv: str
    sig_b64: Optional[str] = None  # v3: firma Ed25519 del autor sobre x39msg:v3:aid:content_hash:cts
    cts: Optional[str] = None      # v3: timestamp ISO del cliente (parte del string firmado)


class E2EKeyModel(BaseModel):
    public_key_jwk: dict


class E2EPQKeyModel(BaseModel):
    xwing_pub_b64: Optional[str] = None
    xwing_ct_b64: Optional[str] = None


def _role(a: dict, email: str) -> str:
    return "A" if email == a["party_a"] else "B"


@notaria_router.get("/agreements/{aid}/messages")
async def get_messages(aid: str, email: str = Depends(current_user)):
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "Acceso restringido")
    msgs = list(nmsg.find({"agreement_id": aid}, {"_id": 0}).sort("ts", 1).limit(500))
    return {"frozen": a["status"] == "sealed", "messages": msgs}


@notaria_router.get("/agreements/{aid}/chain_tip")
async def get_chain_tip(aid: str, email: str = Depends(current_user)):
    """Tip actual de la cadena de hashes del chat. El cliente NO confia en este valor:
    lo recomputa localmente desde sus ct/iv y bloquea la firma si no coincide."""
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "Acceso restringido")
    entries, tip = _build_chat_chain(a)
    return {"tip": tip if entries else None, "count": len(entries)}


@notaria_router.post("/agreements/{aid}/messages")
async def post_message(aid: str, data: MessageModel, request: Request, email: str = Depends(require_csrf)):
    _rate_limit(request, "msg", limit=40, window=60)
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "Acceso restringido")
    if a["status"] == "sealed":
        raise HTTPException(409, "El hilo esta sellado; no admite mas mensajes")
    ct = (data.ct or "").strip()
    iv = (data.iv or "").strip()
    if not ct or not iv or len(ct) > 12000 or len(iv) > 64:
        raise HTTPException(400, "Mensaje cifrado invalido")
    sig_b64 = (data.sig_b64 or "").strip() or None
    cts = (data.cts or "").strip() or None
    if sig_b64:
        if not cts or len(cts) > 40:
            raise HTTPException(400, "Firma v3 requiere cts valido")
        if _b64_len(sig_b64) != 64:
            raise HTTPException(400, "sig_b64 invalida (64 bytes Ed25519)")
    if nmsg.count_documents({"agreement_id": aid}) >= 500:
        raise HTTPException(409, "Limite de 500 mensajes por acuerdo alcanzado")
    msg = {"agreement_id": aid, "sender": email, "ct": ct, "iv": iv, "ts": _now()}
    if sig_b64:
        msg["sig_b64"] = sig_b64
        msg["cts"] = cts
    nmsg.insert_one({**msg})
    return msg


@notaria_router.post("/agreements/{aid}/e2e_key")
async def publish_e2e_key(aid: str, data: E2EKeyModel, email: str = Depends(require_csrf)):
    """Publica la pubkey ECDH P-256 del miembro (para derivar el secreto compartido). No es la sk."""
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "Acceso restringido")
    if a["status"] == "sealed":
        raise HTTPException(409, "El hilo esta sellado")
    jwk = data.public_key_jwk or {}
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not jwk.get("x") or not jwk.get("y"):
        raise HTTPException(400, "Clave publica E2E invalida (se espera EC P-256)")
    pub = {"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"]}
    na.update_one({"agreement_id": aid}, {"$set": {f"e2e_keys.{_role(a, email)}": {"jwk": pub, "at": _now()}}})
    return {"ok": True}


@notaria_router.get("/agreements/{aid}/e2e_keys")
async def get_e2e_keys(aid: str, email: str = Depends(current_user)):
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "Acceso restringido")
    keys = a.get("e2e_keys", {})
    return {"A": (keys.get("A") or {}).get("jwk"), "B": (keys.get("B") or {}).get("jwk")}


# ---- E2E v2: hibrido post-cuantico X-Wing (ML-KEM-768 + X25519, draft IETF) ----
E2E_PQ_SUITE = "XWING-MLKEM768-X25519-v2"
XWING_PK_LEN, XWING_CT_LEN = 1216, 1120


def _b64_len(s: str) -> int:
    try:
        return len(base64.b64decode(s, validate=True))
    except Exception:
        return -1


@notaria_router.post("/agreements/{aid}/e2e_pq_key")
async def publish_e2e_pq_key(aid: str, data: E2EPQKeyModel, email: str = Depends(require_csrf)):
    """Publica material PUBLICO del handshake hibrido X-Wing. Nunca claves privadas.
    Rol A publica su pubkey X-Wing; rol B publica el ciphertext encapsulado."""
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "Acceso restringido")
    if a["status"] == "sealed":
        raise HTTPException(409, "El hilo esta sellado")
    role = _role(a, email)
    entry = {}
    if data.xwing_pub_b64 is not None:
        if role != "A":
            raise HTTPException(400, "Solo el rol A publica la pubkey X-Wing")
        if _b64_len(data.xwing_pub_b64) != XWING_PK_LEN:
            raise HTTPException(400, f"xwing_pub_b64 invalida ({XWING_PK_LEN} bytes X-Wing)")
        entry["xwing_pub_b64"] = data.xwing_pub_b64
    if data.xwing_ct_b64 is not None:
        if role != "B":
            raise HTTPException(400, "Solo el rol B publica la encapsulacion X-Wing")
        if _b64_len(data.xwing_ct_b64) != XWING_CT_LEN:
            raise HTTPException(400, f"xwing_ct_b64 invalida ({XWING_CT_LEN} bytes X-Wing)")
        entry["xwing_ct_b64"] = data.xwing_ct_b64
    if not entry:
        raise HTTPException(400, "Nada que publicar")
    sets = {f"e2e_pq.{role}.{k}": v for k, v in entry.items()}
    sets[f"e2e_pq.{role}.at"] = _now()
    sets["e2e_pq.suite"] = E2E_PQ_SUITE
    na.update_one({"agreement_id": aid}, {"$set": sets})
    return {"ok": True, "suite": E2E_PQ_SUITE}


@notaria_router.get("/agreements/{aid}/e2e_pq_keys")
async def get_e2e_pq_keys(aid: str, email: str = Depends(current_user)):
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "Acceso restringido")
    keys = a.get("e2e_pq", {})
    pub_a = (keys.get("A") or {}).get("xwing_pub_b64")
    ct_b = (keys.get("B") or {}).get("xwing_ct_b64")
    return {"suite": keys.get("suite"),
            "A": {"xwing_pub_b64": pub_a} if pub_a else None,
            "B": {"xwing_ct_b64": ct_b} if ct_b else None}


class SigKeyModel(BaseModel):
    ed25519_pub_b64: str


@notaria_router.post("/agreements/{aid}/sig_key")
async def publish_sig_key(aid: str, data: SigKeyModel, email: str = Depends(require_csrf)):
    """v3: publica la pubkey Ed25519 del miembro para firmas por mensaje. Primera escritura gana."""
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "Acceso restringido")
    if a["status"] == "sealed":
        raise HTTPException(409, "El hilo esta sellado")
    pk = (data.ed25519_pub_b64 or "").strip()
    if _b64_len(pk) != 32:
        raise HTTPException(400, "ed25519_pub_b64 invalida (32 bytes)")
    role = _role(a, email)
    existing = (a.get("sig_keys") or {}).get(role)
    if existing and existing != pk:
        raise HTTPException(409, "Pubkey de firma ya registrada para este rol")
    na.update_one({"agreement_id": aid}, {"$set": {f"sig_keys.{role}": pk}})
    return {"ok": True}


@notaria_router.get("/agreements/{aid}/sig_keys")
async def get_sig_keys(aid: str, email: str = Depends(current_user)):
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "Acceso restringido")
    keys = a.get("sig_keys") or {}
    return {"A": keys.get("A"), "B": keys.get("B")}


def _chat_hash(aid: str) -> str:
    msgs = list(nmsg.find({"agreement_id": aid},
                          {"_id": 0, "sender": 1, "text": 1, "ct": 1, "iv": 1, "ts": 1}).sort("ts", 1).limit(500))
    payload = json.dumps(msgs, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _build_chat_chain(a: dict):
    """Cadena de hashes enlazada (anti-omision/anti-reordenacion) del chat E2E.
    Zero-knowledge: solo content_hash (sha256 del ciphertext), rol A/B y ts.
    Nunca ct/iv ni email. Verificable client-side (el cliente tiene ct/iv) y offline.
      content_hash = sha256(ct||iv)  (o sha256(text) en hilos demo en claro)
      msg_hash     = sha256(prev_hash:content_hash:ts:role)
    Devuelve (entries, tip)."""
    aid = a["agreement_id"]
    pa = a["party_a"]
    msgs = list(nmsg.find({"agreement_id": aid},
                          {"_id": 0, "sender": 1, "text": 1, "ct": 1, "iv": 1, "ts": 1,
                           "sig_b64": 1, "cts": 1}).sort("ts", 1).limit(500))
    entries = []
    prev = "0" * 64
    for i, m in enumerate(msgs):
        body = (m.get("ct", "") + m.get("iv", "")) or m.get("text", "")
        content_hash = hashlib.sha256(body.encode()).hexdigest()
        role = "A" if m.get("sender") == pa else "B"
        ts = m.get("ts", "")
        msg_hash = hashlib.sha256(f"{prev}:{content_hash}:{ts}:{role}".encode()).hexdigest()
        entries.append({"index": i, "ts": ts, "role": role,
                        "content_hash": content_hash, "prev_hash": prev, "msg_hash": msg_hash,
                        "sig_b64": m.get("sig_b64"), "cts": m.get("cts")})
        prev = msg_hash
    return entries, prev


async def _seal(a: dict):
    """Congela el chat, construye la prueba, la firma (ML-DSA) y la ancla (OTS)."""
    chat_h = _chat_hash(a["agreement_id"])
    chain_entries, chain_tip = _build_chat_chain(a)
    is_v2 = len(chain_entries) > 0
    proof = {
        "v": "X39-NOTARIA-2" if is_v2 else "X39-NOTARIA-1",
        "agreement_id": a["agreement_id"],
        "title": a["title"],
        "content_hash": a["content_hash"],
        "chat_hash": chat_h,
        "party_a_fp": _email_fp(a["party_a"]),
        "party_b_fp": _email_fp(a.get("party_b")),
        "payment": a.get("payment"),
        "signed_a": a["signatures"].get("A"),
        "signed_b": a["signatures"].get("B"),
        "sealed_at": _now(),
    }
    if is_v2:
        proof["chat_merkle_root"] = chain_tip
        signed_n = sum(1 for e in chain_entries if e.get("sig_b64"))
        if signed_n:
            proof["msg_sigs"] = {"algorithm": "Ed25519", "signed": signed_n, "total": len(chain_entries)}
            if a.get("sig_keys"):
                proof["sig_keys"] = a["sig_keys"]
            if signed_n == len(chain_entries):
                proof["v"] = "X39-NOTARIA-3"
    payload = json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    proof_hash = hashlib.sha256(payload).hexdigest()
    proof["proof_hash"] = proof_hash
    ots_b64, calendars = await ots_stamp(proof_hash, payload)
    ots_doc = {
        "ots_b64": ots_b64,
        "payload_b64": base64.b64encode(payload).decode(),
        "status": "pending" if ots_b64 else "not_stamped",
        "btc_block": None,
        "calendars": calendars,
        "stamped_at": _now(),
    }
    upd = {"status": "sealed", "sealed_at": proof["sealed_at"], "proof": proof, "ots": ots_doc}
    if is_v2:
        upd["chat_chain"] = {"agreement_id": a["agreement_id"], "v": proof["v"], "entries": chain_entries}
    na.update_one({"agreement_id": a["agreement_id"]}, {"$set": upd})
    a.update(upd)


async def _seal_bg(aid: str):
    """Sella en segundo plano: el firmante ya recibio respuesta; aqui ocurre
    la firma ML-DSA y el anclaje OTS (round-trip de red a los calendarios)."""
    try:
        a = na.find_one({"agreement_id": aid}, {"_id": 0})
        if a and a["status"] == "sealing":
            await _seal(a)
    except Exception:
        # Nunca dejar el acuerdo atascado en 'sealing': revertir permite reintentar.
        na.update_one({"agreement_id": aid, "status": "sealing"},
                      {"$set": {"status": "pending_signatures"}})


@notaria_router.post("/agreements/{aid}/sign")
async def sign_agreement(aid: str, background_tasks: BackgroundTasks, email: str = Depends(require_csrf)):
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "No participas en este acuerdo")
    if a["status"] in ("sealed", "sealing"):
        return _public_view(a, email)
    role = "A" if email == a["party_a"] else "B"
    sigs = a.get("signatures", {})
    sigs[role] = _now()
    both = bool(a.get("party_b")) and "A" in sigs and "B" in sigs
    new_status = "sealing" if both else a["status"]
    na.update_one({"agreement_id": aid}, {"$set": {"signatures": sigs, "status": new_status}})
    a["signatures"] = sigs
    a["status"] = new_status
    # El sellado (firma ML-DSA + anclaje OTS) corre en segundo plano: respuesta inmediata al firmante.
    if both:
        background_tasks.add_task(_seal_bg, aid)
    return _public_view(a, email)


async def _refresh_ots(a: dict) -> dict:
    """Intenta actualizar la prueba OTS contra los calendarios y devuelve estado real."""
    ots = a.get("ots")
    if not ots or not ots.get("ots_b64"):
        return {"status": "not_stamped", "btc_block": None}
    payload = base64.b64decode(ots["payload_b64"])
    ph = a["proof"]["proof_hash"]
    new_b64, info = await ots_upgrade(ph, ots["ots_b64"], payload)
    ots["ots_b64"] = new_b64
    ots["status"] = info["ots_status"]
    ots["btc_block"] = info["btc_block"]
    na.update_one({"agreement_id": a["agreement_id"]}, {"$set": {"ots": ots}})
    return {"status": info["ots_status"], "btc_block": info["btc_block"]}


@notaria_router.post("/agreements/{aid}/ots/refresh")
async def refresh_ots(aid: str, email: str = Depends(require_csrf)):
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not _member(a, email):
        raise HTTPException(403, "Acceso restringido")
    if a["status"] != "sealed":
        raise HTTPException(400, "El acuerdo aun no esta sellado")
    return await _refresh_ots(a)


# ---------- Verificacion publica (sin login) ----------
class VerifyModel(BaseModel):
    hash: str


@notaria_router.post("/verify")
async def verify_public(data: VerifyModel, request: Request):
    _rate_limit(request, "verify", limit=30, window=60)
    h = data.hash.lower().strip()
    if not HEX64.match(h):
        raise HTTPException(400, "Introduce un SHA-256 valido (64 hex)")
    a = na.find_one({"status": "sealed", "$or": [{"content_hash": h}, {"proof.proof_hash": h}]}, {"_id": 0})
    if not a:
        return {"found": False, "hash": h}
    st = await _refresh_ots(a)
    return {
        "found": True,
        "matched": "content" if a["content_hash"] == h else "proof",
        "agreement_id": a["agreement_id"],
        "title": a["title"],
        "content_hash": a["content_hash"],
        "proof_hash": a["proof"]["proof_hash"],
        "sealed_at": a["sealed_at"],
        "party_a_fp": _fp_a(a),
        "party_b_fp": _fp_b(a),
        "payment": a.get("payment"),
        "ots_status": st["status"],
        "btc_block": st["btc_block"],
        "pq": {"algorithm": "ML-DSA-87", "signature_b64": a["pq"].get("signature_b64"), "public_key_b64": a["pq"]["public_key_b64"]} if a.get("pq") else None,
        "cold": a.get("cold"),
    }


@notaria_router.get("/public/{aid}")
async def public_proof(aid: str):
    a = na.find_one({"agreement_id": aid, "status": "sealed"}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Prueba no encontrada")
    st = await _refresh_ots(a)
    return {
        "agreement_id": aid, "title": a["title"], "content_hash": a["content_hash"],
        "proof_hash": a["proof"]["proof_hash"], "sealed_at": a["sealed_at"],
        "party_a_fp": _fp_a(a), "party_b_fp": _fp_b(a),
        "payment": a.get("payment"),
        "ots_status": st["status"], "btc_block": st["btc_block"],
        "pq": {"algorithm": "ML-DSA-87", "signature_b64": a["pq"].get("signature_b64"), "public_key_b64": a["pq"]["public_key_b64"]} if a.get("pq") else None,
        "cold": a.get("cold"),
    }


# ---------- Estado de pago (solo lectura, no custodial) ----------
@notaria_router.get("/agreements/{aid}/payment_status")
async def payment_status(aid: str, request: Request):
    _rate_limit(request, "paystatus", limit=30, window=60)
    a = na.find_one({"agreement_id": aid}, {"_id": 0})
    if not a or not a.get("payment"):
        raise HTTPException(404, "Este acuerdo no tiene un pago asociado")
    pm = a["payment"]
    addr = pm["address"]
    try:
        r = requests.get(f"https://mempool.space/api/address/{addr}", timeout=10)
        d = r.json()
        received = (d.get("chain_stats", {}).get("funded_txo_sum", 0)
                    + d.get("mempool_stats", {}).get("funded_txo_sum", 0))
    except Exception:
        raise HTTPException(502, "No se pudo consultar la cadena Bitcoin")
    expected = pm.get("sats") or 0
    return {
        "address": addr,
        "currency": "BTC",
        "expected_sats": expected,
        "received_sats": received,
        "paid": bool(expected and received >= expected),
        "note": "Saldo recibido en la direccion. La app nunca custodia fondos.",
    }


# ---------- COLD co-firma soberana (Pi 5 air-gapped, ML-DSA-87) ----------
@notaria_router.post("/admin/cold_key")
async def register_cold_key(data: ColdKeyModel, x_admin_token: str = Header(default="")):
    """Registra (pin) la clave publica COLD soberana. La clave privada vive SOLO en el Pi air-gapped."""
    _require_admin(x_admin_token)
    try:
        pk = base64.b64decode(data.public_key_b64)
    except Exception:
        raise HTTPException(400, "public_key_b64 invalida")
    if len(pk) != _mldsa.PUBLIC_KEY_SIZE:
        raise HTTPException(400, f"Tamano de clave ML-DSA-87 invalido (esperado {_mldsa.PUBLIC_KEY_SIZE})")
    fp = hashlib.sha256(pk).hexdigest()
    nmeta.update_one({"_id": "cold_mldsa_pub"},
                     {"$set": {"pk": data.public_key_b64, "fingerprint": fp, "registered_at": _now()}},
                     upsert=True)
    return {"algorithm": "ML-DSA-87", "fingerprint": fp, "registered_at": _now()}


@notaria_router.get("/cold_key")
async def get_cold_key():
    """Clave publica COLD soberana registrada (para verificacion independiente)."""
    ck = _cold_pubkey()
    if not ck:
        return {"registered": False}
    _, pk_b64, fp = ck
    return {"registered": True, "algorithm": "ML-DSA-87", "public_key_b64": pk_b64, "fingerprint": fp}


@notaria_router.post("/agreements/{aid}/cold_signature")
async def upload_cold_signature(aid: str, data: ColdSigModel, x_admin_token: str = Header(default="")):
    """Sube una co-firma ML-DSA-87 producida OFFLINE por el Pi 5 sobre el payload anclado.
    El server SOLO verifica contra la pubkey COLD registrada; la sk nunca lo toca."""
    _require_admin(x_admin_token)
    ck = _cold_pubkey()
    if not ck:
        raise HTTPException(409, "No hay clave COLD registrada. Registra primero /admin/cold_key")
    pk, pk_b64, fp = ck
    a = na.find_one({"agreement_id": aid, "status": "sealed"}, {"_id": 0})
    if not a or not (a.get("ots") or {}).get("payload_b64"):
        raise HTTPException(404, "Acuerdo sellado no encontrado")
    payload = base64.b64decode(a["ots"]["payload_b64"])
    try:
        sig = base64.b64decode(data.signature_b64)
    except Exception:
        raise HTTPException(400, "signature_b64 invalida")
    if not _mldsa.verify(pk, payload, sig):
        raise HTTPException(400, "La firma COLD no verifica sobre el payload anclado")
    cold = {"algorithm": "ML-DSA-87", "tier": "COLD", "signature_b64": data.signature_b64,
            "public_key_b64": pk_b64, "fingerprint": fp, "verified_at": _now()}
    na.update_one({"agreement_id": aid}, {"$set": {"cold": cold}})
    return {"ok": True, "cold": cold}




# ---------- Descarga publica de la prueba (verificacion independiente) ----------
@notaria_router.get("/proof/{aid}.ots")
async def download_proof_ots(aid: str):
    a = na.find_one({"agreement_id": aid, "status": "sealed"}, {"_id": 0})
    if not a or not (a.get("ots") or {}).get("ots_b64"):
        raise HTTPException(404, "Prueba OTS no disponible")
    data = base64.b64decode(a["ots"]["ots_b64"])
    return StreamingResponse(io.BytesIO(data), media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="x39-prueba-{aid}.ots"'})


@notaria_router.get("/proof/{aid}.json")
async def download_proof_json(aid: str):
    a = na.find_one({"agreement_id": aid, "status": "sealed"}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Prueba no disponible")
    if (a.get("ots") or {}).get("payload_b64"):
        payload = base64.b64decode(a["ots"]["payload_b64"])
    else:
        payload = json.dumps(a["proof"], sort_keys=True, separators=(",", ":")).encode()
    return StreamingResponse(io.BytesIO(payload), media_type="text/plain; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="x39-prueba-{aid}.json"'})


def _bundle_readme(aid: str, proof_hash: str, has_ots: bool, has_cold: bool) -> str:
    ots_note = "" if has_ots else "\n> AVISO: este acuerdo aun no tiene prueba OTS adjunta. / NOTE: this agreement has no OTS proof attached yet.\n"
    return f"""# X-39 Notaría — Bundle de evidencia / Evidence bundle

Acuerdo / Agreement: {aid}
Hash de la prueba / Proof hash (SHA-256): {proof_hash}

Este bundle es autocontenido: NO necesitas confiar en X-39 ni en ningun servidor para verificarlo.
This bundle is self-contained: you do NOT need to trust X-39 or any server to verify it.
{ots_note}
## Contenido / Contents

- `proof.json`       Payload canonico sellado (los bytes exactos que se firmaron y anclaron) / canonical sealed payload (the exact bytes that were signed and anchored)
- `proof.json.ots`   Prueba OpenTimestamps (ancla en Bitcoin) / OpenTimestamps proof (Bitcoin anchor)
- `signatures.json`  Firmas ML-DSA-87 (FIPS-204) y claves publicas / ML-DSA-87 signatures and public keys
- `README.md`        Esta guia / this guide

## 1. Integridad / Integrity

```
sha256sum proof.json
```
Debe coincidir con / must equal: `{proof_hash}`

## 2. Fecha anclada en Bitcoin / Bitcoin-anchored date

```
pip install opentimestamps-client
ots verify proof.json.ots
```
Nota: `ots verify` completo requiere un nodo Bitcoin local (verificacion 100% trustless). Sin nodo, usa `ots info proof.json.ots` para inspeccionar la atestacion de bloque / full `ots verify` requires a local Bitcoin node; without one, use `ots info` to inspect the block attestation.
Alternativa sin instalar nada / no-install alternative: sube `proof.json` y `proof.json.ots` a https://opentimestamps.org (verificador independiente).
Si el estado es "pending", el ancla espera confirmacion en bloque; reintenta mas tarde / if "pending", retry later:
```
ots upgrade proof.json.ots && ots verify proof.json.ots
```

## 3. Firma post-cuantica / Post-quantum signature (ML-DSA-87, FIPS-204{', co-firma COLD air-gapped' if has_cold else ''})

> La clave WARM (operador, servidor) fue RETIRADA el 2026-07-16 (SEC-003). Las firmas WARM de acuerdos
> anteriores siguen siendo verificables: la clave publica va embebida en `signatures.json`. En acuerdos
> nuevos, la autoria post-cuantica la aporta exclusivamente la co-firma COLD (sk air-gapped, nunca en red).
> The WARM (server-side operator) key was RETIRED on 2026-07-16 (SEC-003). Historical WARM signatures remain
> verifiable (public key embedded in `signatures.json`). For new agreements, post-quantum authorship is
> provided exclusively by the COLD co-signature (air-gapped sk, never networked).

```
pip install pqcrypto
python3 verify_mldsa.py
```
Contenido de `verify_mldsa.py` / contents:
```python
import json, base64
from pqcrypto.sign import ml_dsa_87
s = json.load(open("signatures.json"))
p = open("proof.json", "rb").read()
for tier in ("warm", "cold"):
    t = s.get(tier)
    if not t:
        continue
    ok = ml_dsa_87.verify(base64.b64decode(t["public_key_b64"]), p, base64.b64decode(t["signature_b64"]))
    print(tier.upper(), "ML-DSA-87:", "VALID" if ok else "INVALID")
```

### 3.5 Firmas por mensaje / Per-message signatures (X39-NOTARIA-3)

Si `chat_chain.json` incluye `sig_b64` en sus entradas, cada mensaje del chat fue firmado Ed25519 por su autor sobre el string `x39msg:v3:<agreement_id>:<content_hash>:<cts>`. Las pubkeys estan ancladas en `proof.json` (`sig_keys`).
If entries carry `sig_b64`, each chat message was Ed25519-signed by its author over that exact string; the public keys are anchored inside `proof.json` (`sig_keys`).

## 4. Vinculo con el documento original / Link to the original document

`proof.json` contiene `content_hash`: el SHA-256 del documento original, que SOLO las partes poseen (nunca se subio al servidor). Calcula el SHA-256 de tu copia local y comparalo.
`proof.json` contains `content_hash`: the SHA-256 of the original document, held ONLY by the parties (it was never uploaded). Hash your local copy and compare.

---
Verificados los 4 pasos, tienes evidencia matematica de existencia, integridad, fecha y autoria — sin depender de ningun servidor, empresa o pais.
With all 4 steps verified, you hold mathematical evidence of existence, integrity, date and authorship — with no dependence on any server, company or country.
"""


@notaria_router.get("/proof/{aid}.zip")
async def download_evidence_bundle(aid: str):
    """Bundle de evidencia autocontenido. ZIP determinista: mismo acuerdo sellado -> mismos bytes."""
    a = na.find_one({"agreement_id": aid, "status": "sealed"}, {"_id": 0})
    if not a or not (a.get("ots") or {}).get("payload_b64"):
        raise HTTPException(404, "Evidencia no disponible")
    payload = base64.b64decode(a["ots"]["payload_b64"])
    ots_raw = base64.b64decode(a["ots"]["ots_b64"]) if a["ots"].get("ots_b64") else None
    proof_hash = a["proof"]["proof_hash"]
    sigs = {
        "agreement_id": aid,
        "title": a.get("title"),
        "proof_hash": proof_hash,
        "content_hash": a.get("content_hash"),
        "sealed_at": a.get("sealed_at"),
        "warm": ({"algorithm": "ML-DSA-87 (FIPS-204)", "tier": "WARM",
                  "note": "clave de operador retirada 2026-07-16 (SEC-003); firma historica verificable / operator key retired; historical signature remains verifiable",
                  "signature_b64": a["pq"].get("signature_b64"),
                  "public_key_b64": a["pq"].get("public_key_b64")} if a.get("pq") else None),
        "cold": a.get("cold"),
        "message_signatures": ({"algorithm": "Ed25519",
                                "keys": a["proof"].get("sig_keys"),
                                "signed": a["proof"]["msg_sigs"]["signed"],
                                "total": a["proof"]["msg_sigs"]["total"]}
                               if (a.get("proof") or {}).get("msg_sigs") else None),
    }
    readme = _bundle_readme(aid, proof_hash, bool(ots_raw), bool(a.get("cold")))
    entries = [("README.md", readme.encode()), ("proof.json", payload)]
    if ots_raw:
        entries.append(("proof.json.ots", ots_raw))
    entries.append(("signatures.json", json.dumps(sigs, ensure_ascii=False, indent=2, sort_keys=True).encode()))
    if a.get("chat_chain"):
        entries.append(("chat_chain.json", json.dumps(a["chat_chain"], ensure_ascii=False, indent=2, sort_keys=True).encode()))
    buf = io.BytesIO()
    stamp = (2009, 1, 3, 18, 15, 5)  # bloque genesis de Bitcoin: timestamps fijos -> ZIP determinista
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in entries:
            zi = zipfile.ZipInfo(name, date_time=stamp)
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip",
                             headers={"Content-Disposition": f'attachment; filename="x39-evidencia-{aid}.zip"'})


# ---------- Certificado PDF ----------
@notaria_router.get("/certificate/{aid}.pdf")
async def certificate_pdf(aid: str):
    a = na.find_one({"agreement_id": aid, "status": "sealed"}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Certificado no disponible (acuerdo no sellado)")
    st = await _refresh_ots(a)
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas as pdfcanvas
    import io
    buf = io.BytesIO()
    c = pdfcanvas.Canvas(buf, pagesize=A4)
    W, H = A4
    ink = colors.HexColor("#161616"); seal = colors.HexColor("#1F5940"); grey = colors.HexColor("#6B6A65")
    c.setStrokeColor(ink); c.setLineWidth(1.2); c.rect(18 * mm, 18 * mm, W - 36 * mm, H - 36 * mm)
    c.setFont("Helvetica-Bold", 10); c.setFillColor(grey)
    c.drawCentredString(W / 2, H - 30 * mm, "X-39 NOTARIA")
    c.setFont("Times-Roman", 26); c.setFillColor(ink)
    c.drawCentredString(W / 2, H - 46 * mm, "Certificado de Acuerdo")
    c.setFont("Times-Italic", 12); c.setFillColor(grey)
    c.drawCentredString(W / 2, H - 54 * mm, "Prueba de contenido y fecha anclada en Bitcoin")
    y = H - 74 * mm
    def row(label, value, mono=False):
        nonlocal y
        c.setFont("Helvetica", 8); c.setFillColor(grey); c.drawString(24 * mm, y, label.upper())
        y -= 5.5 * mm
        c.setFont("Courier" if mono else "Helvetica", 9.5 if mono else 11); c.setFillColor(ink)
        for chunk in [value[i:i + 90] for i in range(0, len(value), 90)] or [""]:
            c.drawString(24 * mm, y, chunk); y -= 5.5 * mm
        y -= 3 * mm
    row("Titulo del acuerdo", a["title"])
    row("Hash del contenido (SHA-256)", a["content_hash"], mono=True)
    row("Hash de la prueba", a["proof"]["proof_hash"], mono=True)
    row("Parte A (huella)", _fp_a(a) or "—", mono=True)
    row("Parte B (huella)", _fp_b(a) or "—", mono=True)
    if a.get("payment"):
        pm = a["payment"]
        row("Pago acordado", f"{pm['amount']} {pm['currency']} — paga la Parte {pm['payer']}")
        row("Direccion de cobro (Bitcoin)", pm["address"], mono=True)
    row("Sellado (UTC)", a["sealed_at"])
    if st["status"] == "anchored_btc":
        row("Ancla Bitcoin", f"CONFIRMADO en bloque #{st['btc_block']}")
    else:
        row("Ancla Bitcoin", "Pendiente de confirmacion (OpenTimestamps)")
    if a.get("pq"):
        row("Firma post-cuantica", "ML-DSA-87 (FIPS-204) — tier WARM historico (clave retirada)", mono=False)
    if a.get("cold"):
        row("Co-firma soberana (COLD)", f"ML-DSA-87 air-gapped · fp {a['cold']['fingerprint'][:16]}", mono=False)
    c.setFillColor(seal); c.circle(W / 2, 40 * mm, 15 * mm, stroke=1, fill=0)
    c.setFont("Times-Bold", 11); c.drawCentredString(W / 2, 42 * mm, "SELLADO")
    c.setFont("Times-Roman", 7); c.drawCentredString(W / 2, 37 * mm, "X-39 NOTARIA")
    c.setFont("Helvetica", 7); c.setFillColor(grey)
    c.drawCentredString(W / 2, 24 * mm, f"Verifica esta prueba: /verificar  ·  id {aid}")
    c.setFont("Helvetica", 6.5)
    c.drawCentredString(W / 2, 19 * mm, "Evidencia criptografica de existencia, integridad y fecha (firma electronica avanzada, eIDAS art. 3(11)).")
    c.drawCentredString(W / 2, 15 * mm, "No es firma cualificada (QES) ni sustituye a un notario publico. Protocolo abierto: github.com/x39matrix/x39matrix")
    c.showPage(); c.save(); buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f'inline; filename="certificado-{aid}.pdf"'})


# ---------- Pagina publica con Open Graph (compartir) ----------
@notaria_router.get("/p/{aid}", response_class=HTMLResponse)
async def public_html(aid: str, request: Request):
    a = na.find_one({"agreement_id": aid, "status": "sealed"}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Prueba no encontrada")
    st = await _refresh_ots(a)
    proto = request.headers.get("x-forwarded-proto", "https")
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    base = f"{proto}://{host}" if host else os.environ.get("REACT_APP_BACKEND_URL", "")
    anchored = st["status"] == "anchored_btc"
    estado = f"Confirmado en bloque Bitcoin #{st['btc_block']}" if anchored else "Pendiente de confirmacion"
    title = f"X-39 Notaria — {_clean(a['title'], 80)}"
    desc = f"Prueba de acuerdo anclada en Bitcoin. {estado}. Verificable por cualquiera, gratis."
    ver = f"{base}/verificar"
    cert = f"{base}/certificado/{aid}"
    og_img = f"{base}/og_notaria.jpg"
    html = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta property="og:type" content="website">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:url" content="{base}/api/notaria/p/{aid}">
<meta property="og:image" content="{og_img}">
<meta property="og:image:width" content="1264">
<meta property="og:image:height" content="848">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{title}">
<meta name="twitter:description" content="{desc}">
<meta name="twitter:image" content="{og_img}">
<style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#F8F7F4;color:#161616;margin:0;padding:40px 20px;display:flex;justify-content:center}}
.card{{background:#fff;border:1px solid #D5D2CA;max-width:640px;width:100%;padding:40px;border-radius:6px}}
h1{{font-family:Georgia,serif;font-weight:500;font-size:28px;margin:0 0 4px}}
.mono{{font-family:'Courier New',monospace;font-size:12px;word-break:break-all;color:#161616}}
.lbl{{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#6B6A65;margin-top:18px}}
.badge{{display:inline-block;padding:6px 14px;border-radius:4px;font-size:13px;margin-top:8px}}
.ok{{background:#1F5940;color:#fff}} .pend{{border:1px solid #D5D2CA;color:#6B6A65}}
a.btn{{display:inline-block;margin-top:24px;background:#161616;color:#fff;text-decoration:none;padding:12px 20px;border-radius:4px}}</style>
</head><body><div class="card">
<div class="lbl">X-39 Notaria</div><h1>{_clean(a['title'], 80)}</h1>
<div class="badge {'ok' if anchored else 'pend'}">{estado}</div>
<div class="lbl">Hash del contenido (SHA-256)</div><div class="mono">{a['content_hash']}</div>
<div class="lbl">Hash de la prueba</div><div class="mono">{a['proof']['proof_hash']}</div>
<div class="lbl">Sellado (UTC)</div><div class="mono">{a['sealed_at']}</div>
{f'<div class="lbl">Bloque Bitcoin</div><div class="mono"><a href="https://mempool.space/block/{st["btc_block"]}" style="color:#1F5940">mempool.space/block/{st["btc_block"]}</a></div>' if anchored else ''}
<a class="btn" href="{cert}">Ver certificado</a>
<a class="btn" style="background:#1F5940;margin-left:8px" href="{ver}">Verificar esta prueba</a>
</div></body></html>"""
    return HTMLResponse(html)


# ---------- Seed demo (acuerdo sellado + OTS, idempotente) ----------
def seed_demo():
    if na.find_one({"agreement_id": "demo0000demo0001"}, {"_id": 0}):
        return
    a_email, b_email = "ana@demo.x39", "beto@demo.x39"
    for e in (a_email, b_email):
        if not nu.find_one({"email": e}):
            nu.insert_one({"email": e, "created_at": _now()})
    content = ("CONTRATO DE SERVICIOS FREELANCE\n\n"
               "Ana (disenadora) entrega la identidad visual completa (logo, paleta, tipografias) "
               "a Beto (cliente) antes del 30/07/2026. Beto paga 800 EUR: 50% al inicio y 50% a la entrega. "
               "La propiedad intelectual se transfiere a Beto al completar el pago. "
               "Este acuerdo queda sellado y anclado en Bitcoin como prueba de fecha y contenido.")
    ch = hashlib.sha256(content.encode()).hexdigest()
    aid = "demo0000demo0001"
    doc = {
        "agreement_id": aid, "title": "Contrato de diseno — Ana y Beto (demo)",
        "content_kind": "text", "content_text": content, "file_name": None,
        "content_hash": ch, "party_a": a_email, "party_b": b_email,
        "invite_token": secrets.token_urlsafe(18),
        "status": "pending_signatures",
        "signatures": {"A": _now(), "B": _now()},
        "created_at": _now(),
    }
    na.insert_one({**doc})
    for s, t in [(a_email, "Hola Beto, te paso el contrato de la identidad visual."),
                 (b_email, "Perfecto Ana. Confirmo los 800 EUR, 50% ahora y 50% a la entrega."),
                 (a_email, "Genial. Sellamos el acuerdo entonces.")]:
        nmsg.insert_one({"agreement_id": aid, "sender": s, "text": t, "ts": _now()})
    fresh = na.find_one({"agreement_id": aid}, {"_id": 0})
    asyncio.run(_seal(fresh))
