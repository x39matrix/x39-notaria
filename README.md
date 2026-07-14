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
| Signature longevity | **ML-DSA-87** (NIST FIPS-204, category 5) over the canonical proof. | Forge proofs even with a future quantum computer. |
| Chat privacy | True E2E: **ECDH P-256** key agreement + **AES-256-GCM** per message, in the browser. | Read the negotiation — it only ever stores ciphertext. |
| Survivability | Self-contained evidence bundle (ZIP), verifiable **offline** with `verify_bundle.py`. | Destroy your evidence by disappearing — the proof outlives the service. |
| Sovereign co-sign | Optional **COLD** ML-DSA-87 co-signature produced on an **air-gapped Raspberry Pi** (see `pi500/`). | Sign as the operator even with full server compromise — the COLD key never touches a networked machine. |

The status "anchored in Bitcoin" is shown **only** when `ots info` reports a
`BitcoinBlockHeaderAttestation`. Pending means pending. The code never fabricates a proof.

## Architecture

```
frontend/  React 19 (CRA + craco) · Tailwind · shadcn/ui
  src/notaria/        Landing, Crear, Acuerdo (E2E chat), Verificar,
                      VerificadorIndependiente, Certificado, e2e.js (WebCrypto), api.js
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
   - signs it with the WARM ML-DSA-87 operator key,
   - stamps `proof_hash` with OpenTimestamps (async, multiple calendars).
4. Anyone can verify: by hash (`POST /verify`), public page (`/p/{id}`), PDF certificate, or the downloadable evidence bundle.

## Evidence bundle (`GET /api/notaria/proof/{id}.zip`)

Deterministic ZIP (fixed timestamps → same sealed agreement, same bytes):

| File | Content |
|---|---|
| `proof.json` | The **exact canonical bytes** that were signed and anchored |
| `proof.json.ots` | OpenTimestamps proof (Bitcoin anchor) |
| `signatures.json` | WARM + COLD ML-DSA-87 signatures and public keys |
| `README.md` | Step-by-step independent verification guide |

Verify offline, zero trust:

```bash
pip install pqcrypto opentimestamps-client   # both optional, checks degrade gracefully
python3 verify_bundle.py x39-evidencia-<id>.zip --document my_original.pdf
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

See `pi500/GUIA_CONCURSO_ES.md` (runbook) and `pi500/pi500_cold_signer.py`.
Master key generated on a machine that has **never touched a network**; only the
public key and signatures cross via USB. The server verifies, never signs COLD.
`pi500/NODO_BTC_PI_ES.md` documents the planned sovereign Bitcoin-node verification.

## Honest limitations

- WARM key lives on the server: it attests pipeline integrity, not operator identity. The COLD tier exists precisely to remove that trust.
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
- La prueba se firma con **ML-DSA-87** (FIPS-204, post-cuántica) y opcionalmente se co-firma con una clave **COLD** generada en una Raspberry Pi air-gapped (`pi500/`).
- El chat es E2E real (ECDH P-256 + AES-256-GCM): el servidor solo almacena ciphertext.
- El bundle de evidencia (ZIP) se verifica **offline** con `verify_bundle.py`: la prueba sobrevive al servicio.

## Verificación independiente en 30 segundos

```bash
python3 verify_bundle.py x39-evidencia-<id>.zip --document mi_original.pdf
```

Comprueba: integridad (SHA-256), firmas ML-DSA-87 WARM/COLD, ancla Bitcoin (OTS) y que el documento sellado es exactamente TU archivo — sin que salga de tu máquina.

## Límites honestos

Firma electrónica avanzada (eIDAS art. 3(11)); no es firma cualificada (QES) ni sustituye a un notario público. La clave WARM vive en el servidor (por eso existe el nivel COLD air-gapped).

Licencia: **AGPL-3.0** — si despliegas una versión modificada como servicio, debes publicar tu código.
