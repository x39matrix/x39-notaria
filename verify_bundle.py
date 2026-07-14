#!/usr/bin/env python3
"""X-39 Notaria — standalone offline evidence bundle verifier.

Verifies an evidence bundle (x39-evidencia-<id>.zip) WITHOUT contacting any
server. You do not need to trust X-39, its operators, or its infrastructure.

Usage:
    python3 verify_bundle.py x39-evidencia-<id>.zip [--document path/to/original.pdf]

Checks:
  1. INTEGRITY   sha256(proof.json) == proof_hash declared in signatures.json
  2. CONSISTENCY content_hash and agreement_id match between proof.json and signatures.json
  3. SIGNATURES  ML-DSA-87 (FIPS-204) WARM and COLD signatures over proof.json bytes
                 (requires `pip install pqcrypto`; skipped gracefully if absent)
  4. BTC ANCHOR  proof.json.ots inspected with the OpenTimestamps CLI if installed
                 (`pip install opentimestamps-client`); reports the Bitcoin block
  5. DOCUMENT    optional: sha256(--document) == content_hash (proves the sealed
                 agreement refers to YOUR exact file; the file never left your machine)

Exit code 0 = all executed checks passed. Non-zero = at least one failure.
"""
import sys
import json
import base64
import hashlib
import shutil
import zipfile
import argparse
import tempfile
import subprocess
from pathlib import Path

OK, FAIL, SKIP = "[ OK ]", "[FAIL]", "[SKIP]"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser(description="X-39 Notaria offline bundle verifier")
    ap.add_argument("bundle", help="x39-evidencia-<id>.zip")
    ap.add_argument("--document", help="original document to compare against content_hash")
    args = ap.parse_args()

    failures = 0

    with zipfile.ZipFile(args.bundle) as z:
        names = set(z.namelist())
        proof = z.read("proof.json")
        sigs = json.loads(z.read("signatures.json"))
        ots_raw = z.read("proof.json.ots") if "proof.json.ots" in names else None

    # 1. Integrity
    ph = sha256(proof)
    if ph == sigs.get("proof_hash"):
        print(f"{OK} integrity: sha256(proof.json) == proof_hash ({ph[:16]}…)")
    else:
        print(f"{FAIL} integrity: sha256(proof.json)={ph} != declared {sigs.get('proof_hash')}")
        failures += 1

    # 2. Consistency
    p = json.loads(proof)
    for field in ("agreement_id", "content_hash"):
        if p.get(field) == sigs.get(field):
            print(f"{OK} consistency: {field} matches ({str(p.get(field))[:24]}…)")
        else:
            print(f"{FAIL} consistency: {field} mismatch proof={p.get(field)} signatures={sigs.get(field)}")
            failures += 1

    # 3. ML-DSA-87 signatures
    try:
        from pqcrypto.sign import ml_dsa_87 as mldsa
        for tier in ("warm", "cold"):
            t = sigs.get(tier)
            if not t:
                print(f"{SKIP} signature {tier.upper()}: not present in this bundle")
                continue
            pk = base64.b64decode(t["public_key_b64"])
            sig = base64.b64decode(t["signature_b64"])
            if mldsa.verify(pk, proof, sig):
                print(f"{OK} signature {tier.upper()}: ML-DSA-87 VALID (pubkey fp {sha256(pk)[:16]}…)")
            else:
                print(f"{FAIL} signature {tier.upper()}: ML-DSA-87 INVALID")
                failures += 1
    except ImportError:
        print(f"{SKIP} signatures: pqcrypto not installed (pip install pqcrypto)")

    # 4. Bitcoin anchor (OTS)
    if not ots_raw:
        print(f"{SKIP} btc anchor: no proof.json.ots in bundle")
    elif shutil.which("ots"):
        with tempfile.TemporaryDirectory() as td:
            pj = Path(td) / "proof.json"
            po = Path(td) / "proof.json.ots"
            pj.write_bytes(proof)
            po.write_bytes(ots_raw)
            subprocess.run(["ots", "upgrade", str(po)], capture_output=True, timeout=60)
            r = subprocess.run(["ots", "info", str(po)], capture_output=True, text=True, timeout=60)
            out = r.stdout + r.stderr
            import re
            m = re.search(r"BitcoinBlockHeaderAttestation\((\d+)\)", out)
            if m:
                print(f"{OK} btc anchor: BitcoinBlockHeaderAttestation block #{m.group(1)}")
                print(f"       full trustless check: ots verify proof.json.ots (needs a local Bitcoin node)")
            elif "PendingAttestation" in out:
                print(f"{SKIP} btc anchor: pending calendar aggregation; re-run later (ots upgrade)")
            else:
                print(f"{FAIL} btc anchor: no Bitcoin attestation found in proof.json.ots")
                failures += 1
    else:
        print(f"{SKIP} btc anchor: ots CLI not installed (pip install opentimestamps-client)")
        print(f"       no-install option: upload proof.json + proof.json.ots to https://opentimestamps.org")

    # 5. Original document
    if args.document:
        dh = sha256(Path(args.document).read_bytes())
        if dh == p.get("content_hash"):
            print(f"{OK} document: sha256({args.document}) == content_hash — this exact file was sealed")
        else:
            print(f"{FAIL} document: sha256={dh} != content_hash={p.get('content_hash')}")
            failures += 1

    print("-" * 64)
    if failures:
        print(f"RESULT: {failures} CHECK(S) FAILED — do not trust this bundle")
        sys.exit(1)
    print("RESULT: all executed checks passed — evidence is mathematically consistent")
    sys.exit(0)


if __name__ == "__main__":
    main()
