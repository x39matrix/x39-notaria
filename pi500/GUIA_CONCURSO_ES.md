# X-39 Notaría — Guía completa del flujo COLD con Raspberry Pi 500

Documento para leer HOY, antes de que llegue el Pi. Todo lo necesario para la clave
soberana air-gapped ML-DSA-87. Producción: https://estado-protocolo.emergent.host

====================================================================
QUÉ ES ESTO Y POR QUÉ
====================================================================
La notaría firma cada acuerdo con ML-DSA-87 (post-cuántico, FIPS-204) en DOS niveles:
  - WARM (ya activo): clave en el servidor. Firma automática al sellar.
  - COLD (esto): clave generada y guardada en el Pi 500 SIN RED. Nunca toca internet.

El servidor SOLO verifica la firma COLD; la clave privada (sk) jamás sale del Pi.
Esto elimina la última vulnerabilidad (clave en disco) y da la "prueba física de
soberanía" que suma ante el jurado del concurso.

Regla de oro: la sk NUNCA se conecta, nunca se sube, nunca se envía por chat.
Solo cruzan datos PÚBLICOS: la pubkey y las firmas.

====================================================================
QUÉ NECESITAS (checklist físico)
====================================================================
[ ] Raspberry Pi 500 + fuente USB-C (viene en el kit)
[ ] Monitor o TV con HDMI + cable micro-HDMI→HDMI (cable viene en el kit)
[ ] microSD 32GB con Raspberry Pi OS (viene en el kit)
[ ] 3 USB Kingston 64GB, verificados con H2testw, etiquetados:
      · SNEAKERNET   (único que toca máquinas con red)
      · COLD-KEY     (backup de la sk cifrada; nunca toca red)
      · PEM-VAULT    (2ª copia del PEM legacy; nunca toca red)

====================================================================
FASE 0 — PREPARAR EL PI (CON RED, UNA SOLA VEZ)
====================================================================
Enciende el Pi con el monitor conectado. Abre un terminal. Con red (WiFi/ethernet):

    sudo apt update && sudo apt install -y build-essential python3-pip
    pip install pqcrypto cryptography

Copia pi500_cold_signer.py al Pi con el USB SNEAKERNET.
Comprueba que importa SIN errores estando aún online:

    python3 pi500_cold_signer.py --help

Si sale la ayuda sin errores -> listo para desconectar.

CORTE DE RED (definitivo):
    - Quita el cable ethernet si lo hay.
    - Desactiva WiFi y Bluetooth (icono arriba a la derecha, o):
        sudo rfkill block wifi
        sudo rfkill block bluetooth
    A partir de aquí el Pi NO se reconecta nunca. NADA de SSH.

====================================================================
FASE 1 — GENERAR LA CLAVE COLD (EN EL PI, OFFLINE)
====================================================================
Antes del keygen, desactiva el swap (evita que la sk descifrada pueda
caer a disco; Raspberry Pi OS lo trae activado por defecto):

    sudo dphys-swapfile swapoff
    sudo systemctl disable dphys-swapfile

Después:

    python3 pi500_cold_signer.py keygen

    - Te pide una passphrase para cifrar la sk (recomendado). APÚNTALA en papel.
      Sin esa passphrase, la sk es inservible. No la guardes en digital.
    - Genera: mldsa87.sk (cifrada, permisos 600) y mldsa87.pk (pública).
    - Muestra un FINGERPRINT (sha256 de la pubkey). APÚNTALO en papel. Es tu ancla
      de identidad: sirve para detectar si un USB corrompe la clave.

Copia al USB COLD-KEY: mldsa87.sk (backup offline de la privada cifrada).
Copia al USB SNEAKERNET: mldsa87.pk (la pública, para registrarla online).

====================================================================
FASE 2 — REGISTRAR LA PUBKEY (ONLINE)
====================================================================
Lleva mldsa87.pk (SNEAKERNET) a una máquina con red. Dos opciones:

Opción A (recomendada, sin exponer el token):
    Pega en el chat con el agente el CONTENIDO de mldsa87.pk + el fingerprint.
    El agente lo registra en producción con el token del servidor (nunca se expone).

Opción B (tú mismo, si tienes el HWG_ADMIN_TOKEN de producción):
    API=https://estado-protocolo.emergent.host
    ADMIN=<HWG_ADMIN_TOKEN>
    PK=$(cat mldsa87.pk)
    curl -s -X POST "$API/api/notaria/admin/cold_key" \
      -H "X-Admin-Token: $ADMIN" -H "Content-Type: application/json" \
      -d "{\"public_key_b64\":\"$PK\"}"
    curl -s "$API/api/notaria/cold_key"    # el fingerprint DEBE coincidir con Fase 1

Si el fingerprint online != el de Fase 1 -> el USB corrompió algo. Aborta y repite.

====================================================================
FASE 3 — CO-FIRMAR UN ACUERDO SELLADO (SNEAKERNET)
====================================================================
1. ONLINE: descarga el payload anclado del acuerdo sellado:
       curl -s "$API/api/notaria/proof/<AID>.json" -o proof-<AID>.json
   Llévalo al Pi con el USB SNEAKERNET.

2. PI (offline): firma
       python3 pi500_cold_signer.py sign \
         --sk mldsa87.sk --pk mldsa87.pk \
         --payload proof-<AID>.json --out sig.b64
   - El script muestra sha256(payload), agreement_id y proof_hash.
   - Compáralos con el certificado del acuerdo (en la web).
   - Solo si coinciden, teclea: FIRMAR
   - Re-verifica la firma offline y genera sig.b64.
   Lleva sig.b64 al online con el USB SNEAKERNET.

3. ONLINE: sube la firma (Opción A: pásasela al agente; Opción B: tú mismo):
       SIG=$(cat sig.b64)
       curl -s -X POST "$API/api/notaria/agreements/<AID>/cold_signature" \
         -H "X-Admin-Token: $ADMIN" -H "Content-Type: application/json" \
         -d "{\"signature_b64\":\"$SIG\"}"
   200 -> co-firma verificada y guardada.  400 -> payload/clave mal, repite Fase 3.

====================================================================
FASE 4 — VERIFICAR (ONLINE)
====================================================================
    curl -s "$API/api/notaria/public/<AID>" | python3 -m json.tool | grep -A6 '"cold"'
También aparece en el certificado PDF y en el verificador independiente de la web.
El bundle de evidencia (.zip) incluirá la firma COLD en signatures.json.

====================================================================
DATOS TÉCNICOS EXACTOS (para el pitch, todos verdaderos)
====================================================================
    Algoritmo:   ML-DSA-87 (FIPS-204) — Dilithium nivel 5, categoría de seguridad máxima
    Pubkey:      2592 bytes
    Firma:       4627 bytes
    Módulo:      pqcrypto.sign.ml_dsa_87 (mismo que verifica el servidor)
    Cifrado sk:  AES-256-GCM + scrypt (n=2^15) sobre la clave privada en el Pi

====================================================================
SI ALGO SALE MAL
====================================================================
- "passphrase incorrecta": la sk está cifrada; teclea la que apuntaste en Fase 1.
- 400 al subir la firma: el payload que firmaste no es el anclado. Vuelve a descargar
  proof-<AID>.json y repite Fase 3. No toques la clave.
- Perdiste la sk: generas otra (Fase 1) y la re-registras (Fase 2). Las co-firmas
  antiguas siguen verificándose con la pubkey vieja; las nuevas usan la nueva.
- NUNCA reconectes el Pi a la red "para ir más rápido". Eso anula todo el propósito.
