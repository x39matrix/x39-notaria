#!/usr/bin/env python3
"""
verify_bundle.py — verificador de referencia offline de X-39 Notaría.

Verifica un bundle de evidencia (x39-evidencia-<aid>.zip) SIN confiar en X-39:
  1. Integridad     : sha256(proof.json) == signatures.proof_hash
  2. Campos cruzados: agreement_id / content_hash / sealed_at coinciden
  3. Cadena de chat : (X39-NOTARIA-2/3) continuidad + msg_hash + tip == chat_merkle_root
  4. Firmas mensaje : (X39-NOTARIA-3) Ed25519 por mensaje, pubkeys ancladas en proof.json
  5. Firma soberana : ML-DSA-87 (FIPS-204) COLD sobre los bytes de proof.json, con la
                      clave PINEADA en TRUSTED_COLD_FINGERPRINTS (ver abajo)
                      (+ WARM historica si el bundle la incluye: informativa, NO soberana)
  6. Ancla Bitcoin  : ots verify proof.json.ots -f proof.json
                      (--bitcoin-node URL: contrasta contra TU nodo, cero terceros)

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

# ---------------------------------------------------------------------------
# RAIZ DE CONFIANZA DE LA CO-FIRMA SOBERANA
#
# Huellas sha256 de las claves publicas ML-DSA-87 generadas en la Raspberry Pi
# 500 aislada (sin red). Una co-firma "cold" SOLO acredita autoridad soberana de
# X-39 si la clave publica que la verifica reduce a una de estas huellas.
#
# Por que esta pineado y no se lee del bundle: signatures.json NO esta cubierto
# por el ancla OpenTimestamps. Comprobar la huella contra la clave que viene en
# el mismo fichero es circular — cualquiera puede generar su par de claves,
# firmar un proof.json falso, incluir su clave y su huella, anclarlo el mismo, y
# obtener un "VALID" con co-firma aparentemente soberana.
#
# Es un CONJUNTO a proposito: permite rotar la clave COLD anadiendo la nueva sin
# invalidar los sellos ya emitidos con la anterior.
#
# Verifica esta huella por un canal independiente de este fichero antes de
# confiar en el. Si no la has contrastado, no has verificado nada: te has fiado.
# ---------------------------------------------------------------------------
TRUSTED_COLD_FINGERPRINTS = {
    # Pi 500 aislada — clave COLD original (en servicio desde 2026-08)
    "8453a25a41d6fe8fcb5647600f042a7c303daaca79b80928534025711981c6a1",
}


class SigError(Exception):
    """Fallo en una co-firma. El llamante decide si es fatal (COLD) o informativo (WARM)."""


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


def b64_decode_strict(label: str, b64: str, expected_len: int) -> bytes:
    """Igual que b64_decode_exact pero lanza SigError en vez de terminar el proceso."""
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as e:
        raise SigError(f"{label}: base64 invalido: {e}")
    if len(raw) != expected_len:
        raise SigError(f"{label}: tamano {len(raw)} bytes, esperado {expected_len}")
    return raw


def b64_decode_exact(label: str, b64: str, expected_len: int) -> bytes:
    try:
        return b64_decode_strict(label, b64, expected_len)
    except SigError as e:
        die(EXIT_SIG, str(e))


def mldsa_verify_ok(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verifica ML-DSA-87 normalizando las convenciones de pqcrypto.

    Las versiones no coinciden en como reportan el resultado:
      - pqcrypto 1.0.0 : devuelve None si la firma es valida y LANZA
                         InvalidSignatureError si no lo es.
      - versiones previas: devuelven True/False.

    Un `if not verify(...)` rechaza las firmas BUENAS bajo la primera convencion.
    Aqui solo se considera fallo la excepcion o un False explicito; el llamante
    debe ademas ejecutar un control negativo con una firma alterada.
    """
    try:
        from pqcrypto.sign import ml_dsa_87
    except ImportError:
        die(EXIT_IO, "pqcrypto no disponible. Instala: pip install pqcrypto")
    try:
        result = ml_dsa_87.verify(pk, msg, sig)
    except Exception:
        return False
    return result is not False


def check_ml_dsa_signature(label: str, block: dict[str, Any], proof_bytes: bytes,
                           trusted: set[str] | None = None) -> str:
    """Verifica una co-firma ML-DSA-87 sobre los bytes crudos de proof.json.

    Si `trusted` es un conjunto de huellas, la clave publica del bundle solo se
    acepta cuando sha256(pk) pertenece a ese conjunto: ahi esta la diferencia
    entre "la firma es consistente consigo misma" y "la firma es de X-39".

    Devuelve la huella sha256 de la clave publica usada. Lanza SigError.
    """
    algo = str(block.get("algorithm", ""))
    if "ML-DSA-87" not in algo:
        raise SigError(f"{label}: algoritmo inesperado: {algo}")
    pk_b64, sig_b64 = block.get("public_key_b64"), block.get("signature_b64")
    if not pk_b64 or not sig_b64:
        raise SigError(f"{label}: falta public_key_b64 o signature_b64")
    pk = b64_decode_strict(f"{label}.public_key", pk_b64, ML_DSA_87_PK_LEN)
    sig = b64_decode_strict(f"{label}.signature", sig_b64, ML_DSA_87_SIG_LEN)

    fp_computed = hashlib.sha256(pk).hexdigest()
    fp_claimed = block.get("fingerprint")
    if fp_claimed and fp_computed != fp_claimed:
        # Coherencia interna del bundle. NO acredita nada por si sola: ambos
        # valores salen del mismo fichero no anclado.
        raise SigError(f"{label}: fingerprint mismatch: claimed={fp_claimed} computed={fp_computed}")
    if trusted is not None and fp_computed not in trusted:
        raise SigError(
            f"{label}: clave NO reconocida. La huella {fp_computed} no figura en "
            f"TRUSTED_COLD_FINGERPRINTS. La firma puede ser valida sobre si misma, "
            f"pero NO procede de la autoridad soberana de X-39."
        )
    if not mldsa_verify_ok(pk, proof_bytes, sig):
        raise SigError(f"{label}: ML-DSA-87.verify FALLO")
    # Control negativo obligatorio: la libreria instalada DEBE rechazar una firma
    # alterada. Si acepta las dos, no esta verificando nada y su "valida" no vale.
    tampered = bytearray(sig)
    tampered[0] ^= 0x01
    if mldsa_verify_ok(pk, proof_bytes, bytes(tampered)):
        die(EXIT_IO, f"{label}: la instalacion de pqcrypto acepta una firma ALTERADA. "
                     "No se puede confiar en su veredicto: revisa la libreria.")
    return fp_computed


def verify_signatures(proof_bytes: bytes, sigs_raw: bytes) -> tuple[list[str], str | None]:
    sigs = parse_json_bytes(sigs_raw, "signatures.json")
    verify_proof_hash(proof_bytes, sigs)
    proof = parse_json_bytes(proof_bytes, "proof.json")
    verify_cross_fields(proof, sigs)
    notes: list[str] = []
    cold_fp: str | None = None
    cold = sigs.get("cold")
    if cold:
        try:
            cold_fp = check_ml_dsa_signature("cold", cold, proof_bytes,
                                             trusted=TRUSTED_COLD_FINGERPRINTS)
        except SigError as e:
            die(EXIT_SIG, str(e))
    else:
        # SEC-003: la co-firma COLD se aplica post-sellado (sneakernet); su ausencia no es
        # detectable criptograficamente. Se advierte, no se falla: el ancla OTS sigue siendo la prueba.
        notes.append("SIN co-firma soberana COLD (el operador aun no co-firmo este sello)")
    warm = sigs.get("warm")
    if warm is not None:
        # SEC-003: la clave WARM vivia en el servidor y fue retirada. Nunca fue soberana:
        # quien controlase el servidor podia firmar con ella. Se informa, no se pinea y
        # no altera el veredicto.
        try:
            warm_fp = check_ml_dsa_signature("warm", warm, proof_bytes)
            notes.append(f"co-firma WARM historica presente y consistente ({warm_fp[:16]}...); "
                         "informativa, NO acredita autoridad (clave de servidor retirada, SEC-003)")
        except SigError as e:
            notes.append(f"co-firma WARM historica NO valida: {e}; informativa, sin efecto "
                         "sobre el veredicto (clave de servidor retirada, SEC-003)")
    if not cold and not warm:
        notes.append("sin ninguna firma ML-DSA-87; la evidencia se sostiene en OTS/Bitcoin + cadena")
    return notes, cold_fp


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
    # Los contadores de proof.json los escribe quien genera el bundle: se contrastan con la
    # cadena real. En v3 TODOS los mensajes deben ir firmados; uno sin firma es fallo.
    total = len(chain.get("entries") or [])
    if total != ms.get("total"):
        die(EXIT_SIG, f"msg_sigs.total={ms.get('total')} pero la cadena trae {total} mensajes")
    if proof.get("v") == "X39-NOTARIA-3" and checked != total:
        die(EXIT_SIG, f"hilo v3 con mensajes SIN firma: firmados={checked} de {total}")


def verify_ots(proof_bytes: bytes, ots_bytes: bytes, bitcoin_node: str | None = None) -> None:
    with tempfile.TemporaryDirectory() as td:
        p, o = Path(td) / "proof.json", Path(td) / "proof.json.ots"
        p.write_bytes(proof_bytes)
        o.write_bytes(ots_bytes)
        cmd = ["ots"]
        if bitcoin_node:
            cmd += ["--bitcoin-node", bitcoin_node]
        cmd += ["verify", str(o), "-f", str(p)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
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
    ap.add_argument("--bitcoin-node", default=None, metavar="URL",
                    help="RPC de tu nodo Bitcoin (http://user:pass@host:8332 o cookie); "
                         "verificacion soberana del ancla sin terceros")
    args = ap.parse_args()
    files = load_zip(args.bundle)
    proof_bytes = files["proof.json"]
    proof = parse_json_bytes(proof_bytes, "proof.json")
    verify_content_hash(proof, args.content)
    verify_chat_chain_v2(files, proof)
    verify_msg_sigs(files, proof)
    notes, cold_fp = verify_signatures(proof_bytes, files["signatures.json"])
    if not args.skip_ots:
        verify_ots(proof_bytes, files["proof.json.ots"], args.bitcoin_node)
    print("VALID" + (" (OTS omitido)" if args.skip_ots else ""))
    if not args.skip_ots and args.bitcoin_node:
        print("  ancla:       verificada contra nodo Bitcoin PROPIO (cero terceros)")
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
    if cold_fp:
        print(f"  co-firma:    COLD ML-DSA-87 valida · clave PINEADA {cold_fp}")
    print(f"  sealed_at:   {proof.get('sealed_at')}  (informativo; la fecha real es OTS/Bitcoin)")
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
