"""GPG + OpenTimestamps crypto proofs for HWG claims — D3 spec.

CYPHERPUNK HONESTY:
- We sign with a LOCAL BOT KEY generated inside this pod (GPG homedir isolated).
  This is NOT the user's sovereign PGP key. Zero custody of the sovereign key.
  The bot key attests only: "this exact text passed through the HWG pipeline
  at this timestamp". It says NOTHING about the underlying truth.
- OTS status semantics (never lie about the anchor):
    not_stamped   = no timestamp attempted.
    pending       = `ots stamp` succeeded; commitment is with the calendars,
                    NOT yet in a Bitcoin block. Contains `PendingAttestation`.
    anchored_btc  = `ots info` reports at least one
                    `BitcoinBlockHeaderAttestation(<block>)`. This is the ONLY
                    condition under which we upgrade the status.
- If any crypto op fails (network, calendars, disk), we return an honest
  `not_stamped` / `signed=False`. We never fabricate a proof.
"""
import os
import asyncio
import base64
import json
import subprocess
import re
import shutil
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Any


# Isolated GPG homedir for the bot key. Never touches ~/.gnupg of anyone.
GPG_HOME = Path(os.environ.get("HWG_GPG_HOME", "/app/backend/hwg/gnupg"))
GPG_HOME.mkdir(parents=True, exist_ok=True)
os.chmod(GPG_HOME, 0o700)

# Resolve binary paths at import time so we don't rely on supervisor's PATH.
OTS_BIN = shutil.which("ots") or "/root/.venv/bin/ots"
GPG_BIN = shutil.which("gpg") or "/usr/bin/gpg"

BOT_NAME = "HWG Notary Bot"
BOT_COMMENT = "pipeline-only, zero custody"
BOT_EMAIL = "hwg-notary@x39matrix.local"

# OTS output workspace (persistent so upgrade can find files later if needed)
OTS_WORK = Path(os.environ.get("HWG_OTS_WORK", "/app/backend/hwg/ots_work"))
OTS_WORK.mkdir(parents=True, exist_ok=True)


def _gpg(*args: str, input_bytes: Optional[bytes] = None,
         timeout: int = 30) -> subprocess.CompletedProcess:
    """Run gpg with the isolated bot homedir."""
    cmd = [GPG_BIN, "--homedir", str(GPG_HOME), "--batch", "--yes",
           "--no-tty", "--pinentry-mode", "loopback", *args]
    return subprocess.run(cmd, input=input_bytes, capture_output=True, timeout=timeout)


def bot_fingerprint() -> Optional[str]:
    """40-char hex fingerprint of the bot signing key, or None if not yet generated."""
    r = _gpg("--list-secret-keys", "--with-colons")
    if r.returncode != 0:
        return None
    for line in r.stdout.decode(errors="replace").splitlines():
        if line.startswith("fpr:"):
            parts = line.split(":")
            if len(parts) > 9 and parts[9]:
                return parts[9]
    return None


def ensure_bot_key() -> str:
    """Idempotent. Generate the bot key on first call. Returns fingerprint."""
    fp = bot_fingerprint()
    if fp:
        return fp
    batch = (
        "%no-protection\n"
        "Key-Type: RSA\n"
        "Key-Length: 4096\n"
        f"Name-Real: {BOT_NAME}\n"
        f"Name-Comment: {BOT_COMMENT}\n"
        f"Name-Email: {BOT_EMAIL}\n"
        "Expire-Date: 0\n"
        "%commit\n"
    )
    r = _gpg("--gen-key", input_bytes=batch.encode(), timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"gpg key gen failed: {r.stderr.decode(errors='replace')}")
    fp = bot_fingerprint()
    if not fp:
        raise RuntimeError("gpg key generated but fingerprint not found")
    return fp


def bot_public_key_ascii() -> str:
    """ASCII-armored public key. Servable at /api/hwg/pgp.asc for public verification."""
    ensure_bot_key()
    r = _gpg("--armor", "--export", BOT_EMAIL)
    if r.returncode != 0 or not r.stdout:
        return ""
    return r.stdout.decode(errors="replace")


def gpg_detach_sign(payload: bytes) -> Tuple[str, str]:
    """Sign `payload` with the bot key. Returns (ascii_armored_signature, fingerprint)."""
    fp = ensure_bot_key()
    r = _gpg("--armor", "--detach-sign", "--local-user", fp, input_bytes=payload)
    if r.returncode != 0:
        raise RuntimeError(f"gpg sign failed: {r.stderr.decode(errors='replace')}")
    return r.stdout.decode(), fp


def gpg_verify(payload: bytes, ascii_sig: str) -> bool:
    """Verify detached signature against payload. True iff signature is a GOODSIG
    from a key in our (isolated) keyring — i.e., the bot itself."""
    ensure_bot_key()
    with tempfile.NamedTemporaryFile(dir=str(GPG_HOME), suffix=".sig",
                                      delete=False) as tf_sig:
        tf_sig.write(ascii_sig.encode())
        sig_path = tf_sig.name
    try:
        r = _gpg("--verify", sig_path, "-", input_bytes=payload)
    finally:
        try:
            os.unlink(sig_path)
        except OSError:
            pass
    return r.returncode == 0


# ---------- OpenTimestamps ----------

_BTC_BLOCK_RE = re.compile(r"BitcoinBlockHeaderAttestation\s*\(\s*(\d+)\s*\)")
_PENDING_RE = re.compile(r"PendingAttestation\s*\(\s*['\"]?(https?://[^'\")\s]+)")


def canonical_payload(claim_dict: dict) -> bytes:
    """Byte-exact canonical serialization: sorted keys, tight separators, UTF-8."""
    return json.dumps(claim_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_ots_pair(sha256_hex: str, payload: bytes,
                    ots_bytes: Optional[bytes] = None) -> Tuple[Path, Path]:
    """Persist payload + optional .ots into OTS_WORK for later upgrade."""
    payload_path = OTS_WORK / f"{sha256_hex}.txt"
    ots_path = OTS_WORK / f"{sha256_hex}.txt.ots"
    payload_path.write_bytes(payload)
    if ots_bytes is not None:
        ots_path.write_bytes(ots_bytes)
    return payload_path, ots_path


async def _run_ots(args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
    """Run the `ots` CLI without blocking the event loop. Raises on timeout."""
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode, stdout, stderr


async def ots_stamp(sha256_hex: str, payload: bytes,
                    timeout: int = 60) -> Tuple[Optional[str], List[str]]:
    """Timestamp `payload`. Returns (ots_proof_b64, calendars_reported).
    (None, []) if the stamp fails (network, calendars). NEVER raises."""
    payload_path, ots_path = _write_ots_pair(sha256_hex, payload)
    try:
        rc, out, err = await _run_ots([OTS_BIN, "stamp", str(payload_path)], timeout)
    except asyncio.TimeoutError:
        return None, []
    if rc != 0 or not ots_path.exists():
        return None, []
    ots_b64 = base64.b64encode(ots_path.read_bytes()).decode()
    calendars: List[str] = []
    for line in (out.decode(errors="replace")
                 + err.decode(errors="replace")).splitlines():
        m = re.search(r"(https?://\S+)", line)
        if m:
            calendars.append(m.group(1))
    return ots_b64, calendars


async def ots_info_probe(sha256_hex: str, ots_b64: str,
                         payload: bytes) -> Dict[str, Any]:
    """Run `ots info` on a proof. Returns dict:
      { ots_status, btc_block, pending_calendars, raw_info_snippet }
    - anchored_btc iff at least one BitcoinBlockHeaderAttestation appears.
    - Otherwise pending if PendingAttestation appears.
    - Otherwise not_stamped (proof malformed / missing).
    """
    _, ots_path = _write_ots_pair(sha256_hex, payload, base64.b64decode(ots_b64))
    try:
        _, out, err = await _run_ots([OTS_BIN, "info", str(ots_path)], 30)
        text = out.decode(errors="replace") + err.decode(errors="replace")
    except asyncio.TimeoutError:
        text = ""
    btc_match = _BTC_BLOCK_RE.search(text)
    pending_matches = _PENDING_RE.findall(text)
    if btc_match:
        status = "anchored_btc"
        btc_block: Optional[int] = int(btc_match.group(1))
    elif pending_matches:
        status = "pending"
        btc_block = None
    else:
        status = "not_stamped"
        btc_block = None
    return {
        "ots_status": status,
        "btc_block": btc_block,
        "pending_calendars": pending_matches,
        "raw_info_snippet": text[:1500],
    }


async def ots_upgrade(sha256_hex: str, ots_b64: str,
                      payload: bytes, timeout: int = 60) -> Tuple[str, Dict[str, Any]]:
    """Attempt `ots upgrade` on a pending proof. Returns (new_ots_b64, info_probe).
    If nothing changed, returns the original b64 + current info probe."""
    _, ots_path = _write_ots_pair(sha256_hex, payload, base64.b64decode(ots_b64))
    try:
        await _run_ots([OTS_BIN, "upgrade", str(ots_path)], timeout)
    except asyncio.TimeoutError:
        pass
    # Clean any .bak file ots writes on successful upgrade
    bak = Path(str(ots_path) + ".bak")
    if bak.exists():
        try:
            bak.unlink()
        except OSError:
            pass
    new_b64 = base64.b64encode(ots_path.read_bytes()).decode() if ots_path.exists() else ots_b64
    info = await ots_info_probe(sha256_hex, new_b64, payload)
    return new_b64, info


# ---------- High-level integration used by the ingestion pipeline ----------

async def attach_crypto_proof(claim_dict: dict, sha256_hex: str,
                              do_stamp: bool = True) -> dict:
    """Produce a CryptoProof-shaped dict for a newly-ingested claim.

    - Always tries GPG sign (should not fail in a healthy pod).
    - Tries OTS stamp if do_stamp=True. Best-effort: if calendars are unreachable,
      returns ots_status='not_stamped' honestly.
    """
    payload = canonical_payload(claim_dict)
    proof: Dict[str, Any] = {
        "gpg_sig_ascii":     None,
        "gpg_fingerprint":   None,
        "gpg_key_role":      "hwg-notary-bot",
        "ots_proof_b64":     None,
        "ots_calendars":     [],
        "ots_status":        "not_stamped",
        "btc_block":         None,
        "btc_block_hash":    None,
        "btc_block_ts_iso":  None,
        "signed":            False,
    }
    try:
        sig, fp = gpg_detach_sign(payload)
        proof["gpg_sig_ascii"] = sig
        proof["gpg_fingerprint"] = fp
        proof["signed"] = True
    except Exception:
        # Signing MUST work in a healthy pod; if it doesn't we still return
        # honestly with signed=False.
        proof["gpg_sig_ascii"] = None
        proof["signed"] = False

    if do_stamp:
        ots_b64, calendars = await ots_stamp(sha256_hex, payload)
        if ots_b64:
            proof["ots_proof_b64"] = ots_b64
            proof["ots_calendars"] = calendars
            proof["ots_status"] = "pending"  # honest: not yet in a BTC block
    return proof


async def verify_proof_live(claim_dict: dict, proof: dict) -> Dict[str, Any]:
    """Live verification against the bot key and current OTS state.
    Read-only: does not upgrade the stamp."""
    payload = canonical_payload(claim_dict)
    out: Dict[str, Any] = {
        "gpg_signed":       False,
        "gpg_verified":     False,
        "gpg_fingerprint":  proof.get("gpg_fingerprint"),
        "ots_status":       proof.get("ots_status", "not_stamped"),
        "btc_block":        proof.get("btc_block"),
        "pending_calendars": [],
    }
    sig = proof.get("gpg_sig_ascii")
    if sig:
        out["gpg_signed"] = True
        try:
            out["gpg_verified"] = gpg_verify(payload, sig)
        except Exception:
            out["gpg_verified"] = False
    ots_b64 = proof.get("ots_proof_b64")
    if ots_b64:
        # Use claim's sha256 if present in the doc, else derive from payload
        import hashlib
        sha_hex = hashlib.sha256(payload).hexdigest()
        info = await ots_info_probe(sha_hex, ots_b64, payload)
        out["ots_status"] = info["ots_status"]
        out["btc_block"] = info["btc_block"]
        out["pending_calendars"] = info["pending_calendars"]
    return out
