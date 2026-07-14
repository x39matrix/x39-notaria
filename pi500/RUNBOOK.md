# RUNBOOK — Primer arranque del Pi 500 COLD (X-39 Notaría)

Ensayo completo verificado en preview el 2026-07-10 (cadena register->sign->upload->verify OK,
firma corrupta rechazada con 400). Este es el guion para el hardware real. Producción:
`API=https://estado-protocolo.emergent.host`

## Fase 0 — Preparar el Pi (con red, UNA vez)
```
pip install pqcrypto cryptography        # o wheels offline: pip install --no-index --find-links ./wheels ...
# copia pi500_cold_signer.py al Pi (USB)
# CORTA LA RED FISICAMENTE. Nunca se reconecta.
```

## Fase 1 — keygen COLD (en el Pi, offline)
```
python3 pi500_cold_signer.py keygen          # sk cifrada (recomendado) | --plain para sk en claro
# genera mldsa87.sk (0600) + mldsa87.pk ; APUNTA el fingerprint
# mldsa87.pk -> USB -> online ; la sk NUNCA sale del Pi
```

## Fase 2 — Registrar la pubkey (online)
```
API=https://estado-protocolo.emergent.host
ADMIN=<HWG_ADMIN_TOKEN de produccion>
PK=$(cat mldsa87.pk)
curl -s -X POST "$API/api/notaria/admin/cold_key" \
  -H "X-Admin-Token: $ADMIN" -H "Content-Type: application/json" \
  -d "{\"public_key_b64\":\"$PK\"}"
curl -s "$API/api/notaria/cold_key"          # confirma; fingerprint debe COINCIDIR con Fase 1
```

## Fase 3 — Firmar un acuerdo sellado (sneakernet)
```
AID=<agreement_id sellado>
curl -s "$API/api/notaria/proof/$AID.json" -o proof-$AID.json   # online -> USB -> Pi
# en el Pi (offline):
python3 pi500_cold_signer.py sign --sk mldsa87.sk --pk mldsa87.pk --payload proof-$AID.json --out sig.b64
# compara sha256(payload)/proof_hash con el certificado, teclea FIRMAR ; sig.b64 -> USB -> online
```

## Fase 4 — Subir la co-firma (online)
```
SIG=$(cat sig.b64)
curl -s -X POST "$API/api/notaria/agreements/$AID/cold_signature" \
  -H "X-Admin-Token: $ADMIN" -H "Content-Type: application/json" \
  -d "{\"signature_b64\":\"$SIG\"}"
# 200 -> co-firma verificada y guardada ; 400 -> payload o clave equivocada, repite Fase 3
```

## Fase 5 — Verificar
```
curl -s "$API/api/notaria/public/$AID" | python3 -m json.tool | grep -A6 '"cold"'
# tier COLD + fingerprint. Tambien en el PDF y el verificador independiente.
```

## Avisos
- Endpoints COLD confirmados vivos en prod (2026-07-10). No hace falta redeploy para este flujo.
- El fingerprint es tu ancla de identidad: si Fase2 != Fase1, el USB corrompio algo. Aborta.
- La sk no se respalda en la nube. Backup solo fisico/offline. Si la pierdes, generas otra y re-registras;
  las co-firmas viejas siguen verificables con la pubkey vieja.
