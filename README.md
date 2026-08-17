# X-39 Notaría

**Trustless agreement sealing anchored to Bitcoin. Post-quantum signed. End-to-end encrypted negotiation.**

Two parties agree on something. X-39 seals the agreement so that its **existence, integrity, date and authorship** can be verified by anyone, forever, offline — without trusting X-39, any company, notary or state.

*Versión en español más abajo.*

---

## Trust model (read this first)

| Property | How it is achieved | What the server can NOT do |
|---|---|---|
| Document privacy | SHA-256 computed **client-side** (Web Crypto). Only the hash reaches the server. | Read your document — it never leaves your device. |
| Date proof | [OpenTimestamps](https://opentimestamps.org) anchor into a **Bitcoin block**. | Backdate or forge the timestamp — Bitcoin PoW seals it. |
| Signature longevity | **ML-DSA-87** (NIST FIPS-204, category 5) co-signature over the canonical proof, produced on an **air-gapped machine**. | Forge proofs even with a future quantum computer — or even with full server compromise. |
| Chat privacy | Post-quantum hybrid E2E: **X-Wing (ML-KEM-768 + X25519)** → HKDF → **AES-256-GCM** per message, in the browser. Legacy threads: ECDH P-256 (read-only). | Read the negotiation — it only ever stores ciphertext. |
| Survivability | Self-contained evidence bundle (ZIP), verifiable **offline** with `verify_bundle.py`. | Destroy your evidence by disappearing — the proof outlives the service. |
| Sovereign co-sign | **COLD** ML-DSA-87 co-signature produced on an **air-gapped Raspberry Pi** (see `pi500/`). Since 2026-07-16 this is the system's **only** post-quantum signing authority. | Sign as the operator even with full server compromise — the COLD key never touches a networked machine. |

The status "anchored in Bitcoin" is shown **only** when `ots info` reports a
`BitcoinBlockHeaderAttestation`. Pending means pending. The code never fabricates a proof.

## Architecture

```
frontend/  React 19 (CRA + craco) · Tailwind · shadcn/ui
  src/notaria/        Landing, Crear, Acuerdo (E2E chat), Verificar,
                      VerificadorIndependiente, Certificado, api.js,
                      e2e2.js (X-Wing PQ hybrid), e2e.js (legacy P-256)
backend/   FastAPI · MongoDB (pymongo)
  server.py           app assembly, CORS, /api/health
  notaria.py          all routes: auth, agreements, E2E chat, sealing,
                      OTS anchoring, public verification, evidence bundle,
                      PDF certificate, COLD co-signature
  hwg/crypto.py       async OpenTimestamps CLI wrappers (stamp / upgrade / info)
pi500/     air-gapped COLD signer (pi500_cold_signer.py) + runbooks (ES)
verify_bundle.py      standalone offline verifier for evidence bundles
```

- Auth: Emergent-managed Google OAuth (server-side session exchange, httpOnly cookie, CSRF token required for signing).
- All API routes are prefixed `/api/notaria/*`.
- Rate limiting: in-memory sliding window per IP+scope (single-process deployment).

## Sealing flow

1. Party A writes the agreement (or hashes a file client-side) → `POST /agreements`.
2. Party B joins via single-use invite link. Negotiation happens in the E2E chat.
3. Both sign (`POST /agreements/{id}/sign`, CSRF-protected). On the second signature the server:
   - freezes the chat and computes `chat_hash`,
   - builds the canonical proof JSON (sorted keys, compact separators),
   - stamps `proof_hash` with OpenTimestamps (async, multiple calendars).
4. The operator co-signs the anchored payload **offline** on the air-gapped signer
   (sneakernet; see `pi500/RUNBOOK_CEREMONIA_COLD.md` for the executed ceremony) and
   uploads the signature — the server only verifies it against the pinned COLD pubkey.
5. Anyone can verify: by hash (`POST /verify`), public page (`/p/{id}`), PDF certificate, or the downloadable evidence bundle.

## Evidence bundle (`GET /api/notaria/proof/{id}.zip`)

Deterministic ZIP (fixed timestamps → same sealed agreement, same bytes):

| File | Content |
|---|---|
| `proof.json` | The **exact canonical bytes** that were signed and anchored |
| `proof.json.ots` | OpenTimestamps proof (Bitcoin anchor) |
| `signatures.json` | COLD sovereign ML-DSA-87 signature + public key (and historical WARM signatures on pre-2026-07-16 agreements) |
| `README.md` | Step-by-step independent verification guide |

Verify offline, zero trust:

```bash
pip install pqcrypto opentimestamps-client   # both optional, checks degrade gracefully
python3 verify_bundle.py x39-evidencia-<id>.zip --document my_original.pdf

# sovereign mode: verify the Bitcoin anchor against YOUR OWN node
# (zero calendars, zero explorers — only your local proof-of-work)
python3 verify_bundle.py x39-evidencia-<id>.zip \
  --bitcoin-node "http://$(cat ~/.bitcoin/.cookie)@127.0.0.1:8332"
```

## Self-hosting

Requirements: Python 3.11+, Node 18+ (yarn), MongoDB, `ots` CLI (`pip install opentimestamps-client`).

```bash
# backend
cd backend
cp .env.example .env        # fill values; HWG_ADMIN_TOKEN gates COLD-key admin endpoints
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8001

# frontend
cd frontend
cp .env.example .env        # REACT_APP_BACKEND_URL = your public URL
yarn && yarn start
```

Route `/api/*` to the backend and everything else to the frontend (any reverse proxy).

## Air-gapped COLD co-signing

See `pi500/RUNBOOK_CEREMONIA_COLD.md` — the **executed** key ceremony (2026-07-16), including
an honest key rotation after a lost passphrase — and `pi500/pi500_cold_signer.py`.
Master key generated on a machine that has **never touched a network**; only the
public key and signatures cross via USB. The server verifies, never signs COLD.

Sovereign anchor verification against your own Bitcoin Core node is live:
`verify_bundle.py --bitcoin-node` (see the command above). A dedicated
Raspberry Pi 5 (NVMe) runs the full, fully-validated Bitcoin Core node —
the air-gapped Pi 500 signer never touches a network.

## Sovereign verification record

Full node, fully validated from genesis — Bitcoin Core 31.1 on dedicated hardware (Raspberry Pi 5, NVMe). Synced 2026-08-14; as of 2026-08-17: blocks = headers = 962866 · verificationprogress = 1 · initialblockdownload = false

All 12 anchor blocks re-verified against this node, in under one second, with zero third parties:

- Foundational tECDSA (Jun 2026): #952131 · #952148 · #952150 · #952174
- June seals (2026-06-22): #954867 · #954873
- First sealed agreement (2026-07-09): #957240
- SME Fund dossier, double attestation (2026-08-07): #961469 · #961470
- Golden Seal, triple attestation, first 100% sovereign run (2026-08-08): #961562 · #961564 · #961602

Reproduce any of them:

    bitcoin-cli getblockhash 952131
    bitcoin-cli getblockheader <hash>

## Key retirement (SEC-003)

On 2026-07-16 the server-side ("WARM") ML-DSA-87 signing key was **retired and deleted**
once the air-gapped path was proven end-to-end. Historical WARM signatures remain
verifiable (the public key is embedded per agreement). Since that date, no networked
machine holds any signing authority in this system.

## Honest limitations

- The COLD co-signature requires a manual sneakernet round-trip per agreement (by design: no automation can touch the air-gapped key).
- New E2E chat threads are post-quantum hybrid (X-Wing); threads created before the upgrade remain on legacy P-256 (read-only, no silent downgrade or upgrade).
- E2E chat keys are per-browser (WebCrypto, non-extractable). A new device cannot decrypt old messages — by design.
- eIDAS: advanced electronic signature material (art. 3(11)); **not** a qualified signature, **not** a substitute for a public notary.
- Rate limiting is in-memory (resets on restart; adequate for single-instance deployment).

## License

[AGPL-3.0](LICENSE). If you run a modified version as a service, you must publish your source. Verification must never depend on trusting an operator — including us.

---

# X-39 Notaría (Español)

**Sellado de acuerdos sin confianza, anclado en Bitcoin. Firmas post-cuánticas. Negociación cifrada extremo a extremo.**

Dos partes acuerdan algo. X-39 lo sella de forma que su **existencia, integridad, fecha y autoría** sean verificables por cualquiera, para siempre, sin conexión — sin confiar en X-39, ni en ninguna empresa, notario o Estado.

## Modelo de confianza

- El documento **nunca se sube**: el SHA-256 se calcula en tu navegador.
- "Anclado en Bitcoin" se muestra **solo** cuando OpenTimestamps confirma un `BitcoinBlockHeaderAttestation`. Pendiente significa pendiente.
- La prueba se ancla en Bitcoin y se co-firma con **ML-DSA-87** (FIPS-204, post-cuántica) desde una clave **COLD** generada en una Raspberry Pi air-gapped (`pi500/`) — desde el 2026-07-16, la única autoridad de firma del sistema.
- El chat es E2E post-cuántico híbrido (**X-Wing: ML-KEM-768 + X25519** → AES-256-GCM): el servidor solo almacena ciphertext. Hilos antiguos: P-256 (solo lectura).
- El bundle de evidencia (ZIP) se verifica **offline** con `verify_bundle.py`: la prueba sobrevive al servicio.

## Verificación independiente en 30 segundos

```bash
python3 verify_bundle.py x39-evidencia-<id>.zip --document mi_original.pdf
```

Comprueba: integridad (SHA-256), firma soberana ML-DSA-87 COLD (y WARM histórica si existe), ancla Bitcoin (OTS) y que el documento sellado es exactamente TU archivo — sin que salga de tu máquina.

## Límites honestos

Firma electrónica avanzada (eIDAS art. 3(11)); no es firma cualificada (QES) ni sustituye a un notario público. La clave WARM de servidor fue retirada y eliminada el 2026-07-16 (SEC-003): ninguna máquina conectada posee autoridad de firma.

Licencia: **AGPL-3.0** — si despliegas una versión modificada como servicio, debes publicar tu código.
