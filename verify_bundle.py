#!/usr/bin/env python3
"""
verify_bundle.py — verificador de referencia offline de X-39 Notaría.

Verifica un bundle de evidencia (x39-evidencia-<aid>.zip) SIN confiar en X-39:
  1. Integridad     : sha256(proof.json) == signatures.proof_hash
  2. Campos cruzados: agreement_id / content_hash / sealed_at coinciden
  3. Cadena de chat : (X39-NOTARIA-2/3) continuidad + msg_hash + tip == chat_merkle_root
  4. Firmas mensaje : (X39-NOTARIA-3) Ed25519 por mensaje, pubkeys ancladas en proof.json
  5. Firma soberana : ML-DSA-87 (FIPS-204) COLD sobre los bytes de proof.json
                      (+ WARM historica si el bundle la incluye)
  6. Ancla Bitcoin  : ots verify proof.json.ots -f proof.json

El mensaje firmado por ML-DSA-87 son los BYTES CRUDOS de proof.json (no proof_hash).
proof.json NO contiene el campo proof_hash: vive en signatures.json y es sha256(proof.json).

Exit codes: 0 VALID · 1 integridad · 2 firma · 3 OTS/Bitcoin · 4 uso/IO
Dependencias opcionales: pip install pqcrypto opentimestamps-client
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

ML_DSA_87_PK_LEN = 2592
ML_DSA_87_SIG_LEN = 4627
EXIT_OK, EXIT_INTEGRITY, EXIT_SIG, EXIT_OTS, EXIT_IO = 0, 1, 2, 3, 4


def die(code: int, msg: str) -> None:
    print(f"FAIL[{code}]: {msg}", file=sys.stderr)
    sys.exit(code)


def load_zip(path: Path) -> dict[str, bytes]:
    if not path.is_file():
        die(EXIT_IO, f"no existe: {path}")
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = set(zf.namelist())
            required = {"proof.json", "proof.json.ots", "signatures.json"}
            missing = required - names
            if missing:
                die(EXIT_IO, f"ZIP incompleto, faltan: {sorted(missing)}")
            return {n: zf.read(n) for n in names}
    except zipfile.BadZipFile as e:
        die(EXIT_IO, f"ZIP invalido: {e}")


def parse_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        die(EXIT_INTEGRITY, f"{label} no es JSON UTF-8 valido: {e}")
    if not isinstance(obj, dict):
        die(EXIT_INTEGRITY, f"{label} no es objeto JSON")
    return obj


def verify_proof_hash(proof_bytes: bytes, sigs: dict[str, Any]) -> None:
    claimed = sigs.get("proof_hash")
    if not isinstance(claimed, str) or len(claimed) != 64:
        die(EXIT_INTEGRITY, "proof_hash mal formado en signatures.json")
    recomputed = hashlib.sha256(proof_bytes).hexdigest()
    if recomputed != claimed:
        die(EXIT_INTEGRITY, f"proof_hash mismatch: claimed={claimed} recomputed={recomputed}")


def verify_cross_fields(proof: dict[str, Any], sigs: dict[str, Any]) -> None:
    for field in ("agreement_id", "content_hash", "sealed_at"):
        pv, sv = proof.get(field), sigs.get(field)
        if pv is not None and sv is not None and pv != sv:
            die(EXIT_INTEGRITY, f"{field} difiere: proof={pv} signatures={sv}")


def b64_decode_exact(label: str, b64: str, expected_len: int) -> bytes:
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as e:
        die(EXIT_SIG, f"{label}: base64 invalido: {e}")
    if len(raw) != expected_len:
        die(EXIT_SIG, f"{label}: tamano {len(raw)} bytes, esperado {expected_len}")
    return raw


def verify_one_signature(label: str, block: dict[str, Any], proof_bytes: bytes) -> None:
    algo = str(block.get("algorithm", ""))
    if "ML-DSA-87" not in algo:
        die(EXIT_SIG, f"{label}: algoritmo inesperado: {algo}")
    pk_b64, sig_b64 = block.get("public_key_b64"), block.get("signature_b64")
    if not pk_b64 or not sig_b64:
        die(EXIT_SIG, f"{label}: falta public_key_b64 o signature_b64")
    pk = b64_decode_exact(f"{label}.public_key", pk_b64, ML_DSA_87_PK_LEN)
    sig = b64_decode_exact(f"{label}.signature", sig_b64, ML_DSA_87_SIG_LEN)
    fp_claimed = block.get("fingerprint")
    if fp_claimed:
        fp_computed = hashlib.sha256(pk).hexdigest()
        if fp_computed != fp_claimed:
            die(EXIT_SIG, f"{label}: fingerprint mismatch: claimed={fp_claimed} computed={fp_computed}")
    try:
        from pqcrypto.sign import ml_dsa_87
    except ImportError:
        die(EXIT_IO, "pqcrypto no disponible. Instala: pip install pqcrypto")
    try:
        valid = ml_dsa_87.verify(pk, proof_bytes, sig)
    except Exception as e:
        die(EXIT_SIG, f"{label}: ml_dsa_87.verify excepcion: {e}")
    if not valid:
        die(EXIT_SIG, f"{label}: ML-DSA-87.verify FALLO")


def verify_signatures(proof_bytes: bytes, sigs_raw: bytes) -> list[str]:
    sigs = parse_json_bytes(sigs_raw, "signatures.json")
    verify_proof_hash(proof_bytes, sigs)
    proof = parse_json_bytes(proof_bytes, "proof.json")
    verify_cross_fields(proof, sigs)
    notes = []
    cold = sigs.get("cold")
    if cold:
        verify_one_signature("cold", cold, proof_bytes)
    else:
        # SEC-003: la co-firma COLD se aplica post-sellado (sneakernet); su ausencia no es
        # detectable criptograficamente. Se advierte, no se falla: el ancla OTS sigue siendo la prueba.
        notes.append("SIN co-firma soberana COLD (el operador aun no co-firmo este sello)")
    warm = sigs.get("warm")
    if warm is not None:
        verify_one_signature("warm", warm, proof_bytes)
    if not cold and not warm:
        notes.append("sin ninguna firma ML-DSA-87; la evidencia se sostiene en OTS/Bitcoin + cadena")
    return notes


def verify_content_hash(proof: dict[str, Any], content_path: Path | None) -> None:
    if content_path is None:
        return
    if not content_path.is_file():
        die(EXIT_IO, f"documento no encontrado: {content_path}")
    computed = hashlib.sha256(content_path.read_bytes()).hexdigest()
    claimed = proof.get("content_hash")
    if computed != claimed:
        die(EXIT_INTEGRITY, f"content_hash mismatch: proof={claimed} file={computed}")


def verify_chat_chain_v2(files: dict[str, bytes], proof: dict[str, Any]) -> None:
    """Solo X39-NOTARIA-2. Recomputa cada msg_hash desde content_hash+ts+role,
    valida la continuidad prev_hash y que el tip == chat_merkle_root firmado."""
    if proof.get("v", "") not in ("X39-NOTARIA-2", "X39-NOTARIA-3"):
        return
    if "chat_chain.json" not in files:
        die(EXIT_INTEGRITY, "v2 requiere chat_chain.json en el ZIP")
    chain = parse_json_bytes(files["chat_chain.json"], "chat_chain.json")
    if chain.get("agreement_id") != proof.get("agreement_id"):
        die(EXIT_INTEGRITY, "chat_chain agreement_id no coincide con proof")
    entries = chain.get("entries")
    if not entries:
        die(EXIT_INTEGRITY, "chat_chain vacia")
    prev = "0" * 64
    for i, e in enumerate(entries):
        if e.get("prev_hash") != prev:
            die(EXIT_INTEGRITY, f"cadena rota en indice {i}: prev_hash mismatch")
        role, ch, ts = e.get("role"), e.get("content_hash"), e.get("ts", "")
        if role not in ("A", "B"):
            die(EXIT_INTEGRITY, f"indice {i}: role invalido: {role}")
        recomputed = hashlib.sha256(f"{prev}:{ch}:{ts}:{role}".encode()).hexdigest()
        if recomputed != e.get("msg_hash"):
            die(EXIT_INTEGRITY, f"indice {i}: msg_hash no deriva de content_hash/ts/role")
        prev = e["msg_hash"]
    expected = proof.get("chat_merkle_root")
    if not expected:
        die(EXIT_INTEGRITY, "v2 sin chat_merkle_root en proof.json")
    if prev != expected:
        die(EXIT_INTEGRITY, f"tip de cadena {prev} != proof.chat_merkle_root {expected}")


def verify_msg_sigs(files: dict[str, bytes], proof: dict[str, Any]) -> None:
    """X39-NOTARIA-3: firmas Ed25519 por mensaje sobre x39msg:v3:<aid>:<content_hash>:<cts>.
    Pubkeys ancladas en proof.json (sig_keys). No-repudio de autoria por mensaje."""
    ms = proof.get("msg_sigs")
    if not ms:
        return
    keys = proof.get("sig_keys") or {}
    if not keys:
        die(EXIT_SIG, "msg_sigs presente pero sin sig_keys en proof.json")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        die(EXIT_IO, "cryptography no disponible. Instala: pip install cryptography")
    pks = {}
    for role, b in keys.items():
        raw = b64_decode_exact(f"sig_keys.{role}", b, 32)
        pks[role] = Ed25519PublicKey.from_public_bytes(raw)
    chain = parse_json_bytes(files["chat_chain.json"], "chat_chain.json")
    aid = proof.get("agreement_id")
    checked = 0
    for i, e in enumerate(chain.get("entries") or []):
        s = e.get("sig_b64")
        if not s:
            continue
        role, ch, cts = e.get("role"), e.get("content_hash"), e.get("cts")
        if role not in pks:
            die(EXIT_SIG, f"indice {i}: firma presente sin pubkey para rol {role}")
        if not cts:
            die(EXIT_SIG, f"indice {i}: firma sin cts")
        raw_sig = b64_decode_exact(f"entries[{i}].sig", s, 64)
        try:
            pks[role].verify(raw_sig, f"x39msg:v3:{aid}:{ch}:{cts}".encode())
        except Exception:
            die(EXIT_SIG, f"indice {i}: firma Ed25519 INVALIDA (rol {role})")
        checked += 1
    if checked != ms.get("signed"):
        die(EXIT_SIG, f"msg_sigs.signed={ms.get('signed')} pero verificadas={checked}")


def verify_ots(proof_bytes: bytes, ots_bytes: bytes) -> None:
    with tempfile.TemporaryDirectory() as td:
        p, o = Path(td) / "proof.json", Path(td) / "proof.json.ots"
        p.write_bytes(proof_bytes)
        o.write_bytes(ots_bytes)
        try:
            r = subprocess.run(["ots", "verify", str(o), "-f", str(p)],
                               capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            die(EXIT_IO, "comando 'ots' no encontrado. Instala: pip install opentimestamps-client")
        except subprocess.TimeoutExpired:
            die(EXIT_OTS, "ots verify timeout (120s)")
        if r.returncode != 0:
            die(EXIT_OTS, f"ots verify fallo:\n{r.stdout}\n{r.stderr}")


def main() -> None:
    ap = argparse.ArgumentParser(description="X-39 Notaria - verificador de referencia offline")
    ap.add_argument("bundle", type=Path, help="x39-evidencia-<aid>.zip")
    ap.add_argument("--content", type=Path, default=None, help="documento original (verifica content_hash)")
    ap.add_argument("--skip-ots", action="store_true", help="omitir OTS (entornos sin 'ots'/nodo)")
    args = ap.parse_args()
    files = load_zip(args.bundle)
    proof_bytes = files["proof.json"]
    proof = parse_json_bytes(proof_bytes, "proof.json")
    verify_content_hash(proof, args.content)
    verify_chat_chain_v2(files, proof)
    verify_msg_sigs(files, proof)
    notes = verify_signatures(proof_bytes, files["signatures.json"])
    if not args.skip_ots:
        verify_ots(proof_bytes, files["proof.json.ots"])
    print("VALID" + (" (OTS omitido)" if args.skip_ots else ""))
    for n in notes:
        print(f"  AVISO:       {n}")
    print(f"  version:     {proof.get('v')}")
    print(f"  agreement:   {proof.get('agreement_id')}")
    print(f"  title:       {proof.get('title')}")
    print(f"  proof_hash:  {hashlib.sha256(proof_bytes).hexdigest()}")
    print(f"  content:     {proof.get('content_hash')}")
    if proof.get("v") in ("X39-NOTARIA-2", "X39-NOTARIA-3"):
        print(f"  chat_root:   {proof.get('chat_merkle_root')}  ({len(json.loads(files['chat_chain.json'])['entries'])} mensajes encadenados)")
    if proof.get("msg_sigs"):
        print(f"  msg_sigs:    Ed25519 {proof['msg_sigs']['signed']}/{proof['msg_sigs']['total']} verificadas")
    print(f"  sealed_at:   {proof.get('sealed_at')}  (informativo; la fecha real es OTS/Bitcoin)")
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
