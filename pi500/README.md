# X-39 Notaría — Firmante COLD air-gapped (Raspberry Pi 500)

Co-firma soberana ML-DSA-87 (FIPS-204). La clave privada **nunca** toca el servidor.
Sin red en el Pi. Sin Iroh. Sin Ollama. Una sola dependencia: `pqcrypto`.

## Contrato (verificado contra el backend `notaria.py`)
- Los bytes a firmar son **exactamente** el contenido de
  `GET /api/notaria/proof/<aid>.json` (= `base64.b64decode(ots.payload_b64)`,
  el pre-imagen del `proof_hash` anclado en Bitcoin vía OpenTimestamps).
- Mismo módulo que el verificador del server: `pqcrypto.sign.ml_dsa_87`.
  Pubkey 2592 B · firma 4627 B.
- El server solo verifica: `POST /agreements/<aid>/cold_signature` → 200 si
  `ml_dsa_87.verify(cold_pk, payload, sig)` pasa; si no → 400.

## Preparación del Pi (una vez, offline)
```
pip install pqcrypto            # firma + verify
pip install cryptography        # solo si cifras la sk (default)
```

## 1 · keygen (una vez, en el Pi aislado)
```
python3 pi500_cold_signer.py keygen            # sk cifrada con passphrase (recomendado)
python3 pi500_cold_signer.py keygen --plain    # sk en claro (Pi dedicado y custodiado)
```
Copia `mldsa87.pk` al online y regístralo **una vez**:
```
POST /api/notaria/admin/cold_key   (header X-Admin-Token: HWG_ADMIN_TOKEN)
body: {"public_key_b64": "<contenido de mldsa87.pk>"}
```

## 2 · sign (por cada acuerdo, en el Pi)
Descarga en el online `proof-<aid>.json` y llévalo por USB al Pi. Luego:
```
python3 pi500_cold_signer.py sign \
    --sk mldsa87.sk --pk mldsa87.pk \
    --payload proof-<aid>.json --out sig.b64
```
El script muestra `sha256(payload)`, `agreement_id` y `proof_hash` para que
los compares con el certificado, exige teclear `FIRMAR`, y re-verifica offline
antes de emitir `sig.b64`.

## 3 · subir la firma (en el online)
```
POST /api/notaria/agreements/<aid>/cold_signature   (X-Admin-Token)
body: {"signature_b64": "<contenido de sig.b64>"}
```

## verify (sanity check offline, opcional)
```
python3 pi500_cold_signer.py verify --pk mldsa87.pk --payload proof-<aid>.json --sig sig.b64
```
