// Chat E2E v2 — hibrido post-cuantico X-Wing (ML-KEM-768 + X25519, draft IETF).
// El rol A publica su pubkey X-Wing (1216 B); el rol B encapsula y publica el ciphertext (1120 B).
// Secreto compartido (32 B) -> HKDF-SHA256 con separacion de dominio por acuerdo -> AES-256-GCM.
// Material privado (seed de A / secreto encapsulado de B) SOLO en localStorage del dispositivo.
// Suite fija: XWING-MLKEM768-X25519-v2. Sin downgrade a v1 (P-256) una vez iniciado.
import { XWing } from '@noble/post-quantum/hybrid.js';

const SUITE = 'XWING-MLKEM768-X25519-v2';

const b64 = {
  enc: (u8) => btoa(String.fromCharCode(...u8)),
  dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

// Identidad del rol A: seed de 32 B en localStorage -> keygen determinista X-Wing.
function getIdentityA(userId) {
  const store = `nt_e2e2_${userId}`;
  let seed = null;
  try {
    const saved = JSON.parse(localStorage.getItem(store) || 'null');
    if (saved?.seed) seed = b64.dec(saved.seed);
  } catch { /* se regenera */ }
  if (!seed || seed.length !== 32) {
    seed = crypto.getRandomValues(new Uint8Array(32));
    localStorage.setItem(store, JSON.stringify({ seed: b64.enc(seed), suite: SUITE }));
  }
  const { publicKey, secretKey } = XWing.keygen(seed);
  return { pubB64: b64.enc(publicKey), secretKey };
}

// Rol B: encapsula contra la pubkey de A, o reutiliza la encapsulacion guardada de este acuerdo
// (la reutilizacion exige que coincidan la pub de A y el ct ya publicado; si A roto su clave, re-encapsula).
function encapsulate(aid, userId, peerPubB64, publishedCtB64) {
  const store = `nt_e2e2_kem_${aid}_${userId}`;
  try {
    const d = JSON.parse(localStorage.getItem(store) || 'null');
    if (d?.pk === peerPubB64 && d?.ct && d?.ss && (!publishedCtB64 || d.ct === publishedCtB64)) {
      return { ctB64: d.ct, ss: b64.dec(d.ss) };
    }
  } catch { /* re-encapsula */ }
  const { cipherText, sharedSecret } = XWing.encapsulate(b64.dec(peerPubB64));
  const ctB64 = b64.enc(cipherText);
  localStorage.setItem(store, JSON.stringify({ pk: peerPubB64, ct: ctB64, ss: b64.enc(sharedSecret), suite: SUITE }));
  return { ctB64, ss: sharedSecret };
}

// Rol A: decapsula el ciphertext publicado por B (determinista: re-derivable en cada sesion).
function decapsulate(identity, ctB64) {
  return XWing.decapsulate(b64.dec(ctB64), identity.secretKey);
}

// ss -> HKDF-SHA256 (WebCrypto nativo) -> clave AES-256-GCM no extraible.
async function deriveKey(aid, ss) {
  const te = new TextEncoder();
  const ikm = await crypto.subtle.importKey('raw', ss, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: te.encode(`x39-notaria-e2e|${SUITE}`), info: te.encode(`aid:${aid}`) },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export const e2e2 = { SUITE, getIdentityA, encapsulate, decapsulate, deriveKey };
