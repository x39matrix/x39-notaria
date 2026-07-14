#!/usr/bin/env python3
# X-39 Notaria — pi500_cold_signer.py
# Firmante COLD air-gapped para Raspberry Pi 500. ML-DSA-87 (FIPS-204).
# SIN RED. SIN Iroh. SIN Ollama. Dependencia unica: pqcrypto.
#
#   Pi aislado (una vez):   pip install pqcrypto
#
# Contrato exacto verificado contra el backend (notaria.py):
#   - El server SOLO verifica. La clave privada (sk) NUNCA sale del Pi.
#   - Los bytes a firmar son EXACTAMENTE el contenido de
#     GET /api/notaria/proof/<aid>.json  (= base64.b64decode(ots.payload_b64),
#     el pre-imagen del proof_hash anclado en Bitcoin via OpenTimestamps).
#   - Mismo modulo que el verificador del server: pqcrypto.sign.ml_dsa_87
#     pubkey 2592 B  ·  firma 4627 B.
#
# Flujo sneakernet (3 pasos, USB):
#   1. ONLINE:  descarga proof-<aid>.json  ->  USB
#   2. PI 500:  python3 pi500_cold_signer.py sign --sk mldsa87.sk \
#                        --payload proof-<aid>.json --out sig.b64
#   3. ONLINE:  registra pubkey una vez  ->  POST /api/notaria/admin/cold_key
#               sube la firma            ->  POST /api/notaria/agreements/<aid>/cold_signature
#
# La verificacion de correspondencia real ocurre en el server; este script
# ademas re-verifica offline antes de emitir (candado local).

import sys, os, json, base64, hashlib, getpass, argparse

try:
    from pqcrypto.sign import ml_dsa_87 as mldsa
except ImportError:
    sys.exit("[!] falta pqcrypto. En el Pi aislado:  pip install pqcrypto")


def die(m):
    sys.exit(f"[!] {m}")


def fp(pk_bytes):
    return hashlib.sha256(pk_bytes).hexdigest()


# ---------- cifrado opcional de la sk (AES-GCM + scrypt), stdlib pura ----------
MAGIC = b"X39SKv1\n"

def _derive(passphrase, salt):
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=2**15, r=8, p=1, dklen=32)

def _encrypt_sk(sk, passphrase):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        die("cifrado pide 'cryptography' (pip install cryptography) o usa --plain")
    salt = os.urandom(16); nonce = os.urandom(12)
    ct = AESGCM(_derive(passphrase, salt)).encrypt(nonce, sk, None)
    return MAGIC + salt + nonce + ct

def _decrypt_sk(blob, passphrase):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce, ct = blob[8:24], blob[24:36], blob[36:]
    return AESGCM(_derive(passphrase, salt)).decrypt(nonce, ct, None)

def _load_sk(path):
    raw = open(path, "rb").read()
    if raw[:8] == MAGIC:
        pw = os.environ.get("X39_SK_PASS") or getpass.getpass("Passphrase de la sk COLD: ")
        try:
            return _decrypt_sk(raw, pw)
        except Exception:
            die("passphrase incorrecta o sk corrupta")
    return base64.b64decode(raw) if len(raw) != mldsa.SECRET_KEY_SIZE else raw


# ---------- keygen ----------
def cmd_keygen(a):
    pk, sk = mldsa.generate_keypair()
    if len(pk) != mldsa.PUBLIC_KEY_SIZE or len(sk) != mldsa.SECRET_KEY_SIZE:
        die("tamanos ML-DSA-87 inesperados; aborta")
    if a.plain:
        open(a.sk, "wb").write(sk)
    else:
        pw = os.environ.get("X39_SK_PASS") or getpass.getpass("Passphrase para cifrar la sk COLD: ")
        if not pw:
            die("passphrase vacia; usa --plain si de verdad la quieres en claro")
        open(a.sk, "wb").write(_encrypt_sk(sk, pw))
    os.chmod(a.sk, 0o600)
    pk_b64 = base64.b64encode(pk).decode()
    open(a.pk, "w").write(pk_b64)
    print("=" * 68)
    print(" CLAVE COLD ML-DSA-87 GENERADA (offline). La sk NO sale del Pi.")
    print("=" * 68)
    print(f"  sk   -> {a.sk}  ({'EN CLARO' if a.plain else 'cifrada AES-GCM'})")
    print(f"  pk   -> {a.pk}")
    print(f"  fingerprint = {fp(pk)}")
    print("-" * 68)
    print(" Registra la pubkey UNA vez desde el online (X-Admin-Token):")
    print("   POST /api/notaria/admin/cold_key")
    print('   body: {"public_key_b64": "%s...%s"}' % (pk_b64[:24], pk_b64[-12:]))
    print(" (copia el contenido completo de %s)" % a.pk)


# ---------- sign ----------
def cmd_sign(a):
    payload = open(a.payload, "rb").read()
    sk = _load_sk(a.sk)
    if len(sk) != mldsa.SECRET_KEY_SIZE:
        die(f"sk tamano {len(sk)} != {mldsa.SECRET_KEY_SIZE}")

    print("=" * 68)
    print(" X-39 COLD — CONFIRMACION SOBERANA (offline, sin red)")
    print("=" * 68)
    print(f"  payload      = {a.payload}  ({len(payload)} B)")
    print(f"  sha256(payload) = {hashlib.sha256(payload).hexdigest()}")
    try:
        proof = json.loads(payload)
        print(f"  agreement_id = {proof.get('agreement_id')}")
        print(f"  proof_hash   = {proof.get('proof_hash')}")
        print(f"  sealed_at    = {proof.get('sealed_at')}")
    except Exception:
        print("  (payload no es JSON legible; se firma tal cual)")
    print("-" * 68)
    if input(" Si el sha256(payload) coincide con el certificado, escribe FIRMAR: ").strip().upper() != "FIRMAR":
        die("cancelado por el operador. No se firmo nada.")

    sig = mldsa.sign(sk, payload)
    if len(sig) != mldsa.SIGNATURE_SIZE:
        die(f"firma {len(sig)} B != {mldsa.SIGNATURE_SIZE}")
    # candado local: re-verificar offline con la pk derivable? necesitamos pk.
    if a.pk and os.path.isfile(a.pk):
        pk = base64.b64decode(open(a.pk).read().strip())
        if not mldsa.verify(pk, payload, sig):
            die("la firma NO verifica offline contra la pk. Aborta.")
        print("[verify] OK offline: la firma verifica bajo la pubkey registrada.")
    else:
        print("[verify] AVISO: sin --pk no re-verifico offline; el server la validara (400 si no).")

    b64 = base64.b64encode(sig).decode()
    open(a.out, "w").write(b64)
    print(f"[sig] {len(sig)} B  sha256={hashlib.sha256(sig).hexdigest()}")
    print(f"[sig] b64 -> {a.out}")
    print("-" * 68)
    print(" Retorno al online -> POST /api/notaria/agreements/<aid>/cold_signature")
    print('   body: {"signature_b64": "<contenido de %s>"}' % a.out)


# ---------- verify (sanity offline) ----------
def cmd_verify(a):
    payload = open(a.payload, "rb").read()
    pk = base64.b64decode(open(a.pk).read().strip())
    sig = base64.b64decode(open(a.sig).read().strip())
    ok = mldsa.verify(pk, payload, sig)
    print(f"fingerprint pk = {fp(pk)}")
    print(f"sha256(payload) = {hashlib.sha256(payload).hexdigest()}")
    print("VERIFICA" if ok else "NO VERIFICA")
    sys.exit(0 if ok else 1)


def main():
    p = argparse.ArgumentParser(description="X-39 Notaria — firmante COLD air-gapped ML-DSA-87")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="genera el par COLD (una vez, en el Pi)")
    g.add_argument("--sk", default="mldsa87.sk")
    g.add_argument("--pk", default="mldsa87.pk")
    g.add_argument("--plain", action="store_true", help="guardar sk en claro (default: cifrada)")
    g.set_defaults(func=cmd_keygen)

    s = sub.add_parser("sign", help="firma el payload anclado (offline)")
    s.add_argument("--sk", required=True)
    s.add_argument("--payload", required=True, help="proof-<aid>.json descargado del online")
    s.add_argument("--pk", default="mldsa87.pk", help="para re-verificar offline (recomendado)")
    s.add_argument("--out", default="sig.b64")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="sanity check offline (pk + payload + sig)")
    v.add_argument("--pk", required=True)
    v.add_argument("--payload", required=True)
    v.add_argument("--sig", required=True)
    v.set_defaults(func=cmd_verify)

    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
