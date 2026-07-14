// Cifrado extremo-a-extremo del chat: ECDH P-256 + AES-256-GCM (WebCrypto).
// La clave privada vive SOLO en localStorage del dispositivo; nunca sale del navegador.
// El servidor solo ve la pubkey ECDH y los pares {ct, iv}. No puede leer el texto.

const b64 = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

async function getIdentity(userId) {
  const store = `nt_e2e_${userId}`;
  const saved = localStorage.getItem(store);
  if (saved) {
    const { priv, pub } = JSON.parse(saved);
    const privKey = await crypto.subtle.importKey('jwk', priv, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
    return { privKey, pubJwk: pub };
  }
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const full = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const pub = { kty: 'EC', crv: 'P-256', x: full.x, y: full.y };
  localStorage.setItem(store, JSON.stringify({ priv, pub }));
  const privKey = await crypto.subtle.importKey('jwk', priv, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
  return { privKey, pubJwk: pub };
}

async function deriveKey(privKey, peerPubJwk) {
  const peer = await crypto.subtle.importKey('jwk', { ...peerPubJwk, ext: true }, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  return crypto.subtle.deriveKey({ name: 'ECDH', public: peer }, privKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptMsg(aesKey, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const buf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(text));
  return { ct: b64.enc(buf), iv: b64.enc(iv) };
}

async function decryptMsg(aesKey, ct, iv) {
  const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(iv) }, aesKey, b64.dec(ct));
  return new TextDecoder().decode(buf);
}

export const e2e = { getIdentity, deriveKey, encryptMsg, decryptMsg };
