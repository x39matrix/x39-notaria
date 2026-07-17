// v3: firmas Ed25519 por mensaje (no-repudio de autoria). La sk vive SOLO en
// localStorage del dispositivo (nt_sig_<email>); la pubkey se ancla en el proof.
// String firmado: x39msg:v3:<aid>:<content_hash>:<cts>  (content_hash = sha256(utf8(ct+iv))).
import { ed25519 } from '@noble/curves/ed25519.js';

const b64 = {
  enc: (u8) => btoa(String.fromCharCode(...u8)),
  dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

function getIdentity(userId) {
  const store = `nt_sig_${userId}`;
  let sk = null;
  try {
    const saved = JSON.parse(localStorage.getItem(store) || 'null');
    if (saved?.sk) sk = b64.dec(saved.sk);
  } catch { /* se regenera */ }
  if (!sk || sk.length !== 32) {
    sk = crypto.getRandomValues(new Uint8Array(32));
    localStorage.setItem(store, JSON.stringify({ sk: b64.enc(sk), alg: 'Ed25519' }));
  }
  return { sk, pubB64: b64.enc(ed25519.getPublicKey(sk)) };
}

function signedString(aid, contentHash, cts) {
  return `x39msg:v3:${aid}:${contentHash}:${cts}`;
}

function signMsg(identity, aid, contentHash, cts) {
  const msg = new TextEncoder().encode(signedString(aid, contentHash, cts));
  return b64.enc(ed25519.sign(msg, identity.sk));
}

function verifyMsg(pubB64, aid, contentHash, cts, sigB64) {
  const msg = new TextEncoder().encode(signedString(aid, contentHash, cts));
  try { return ed25519.verify(b64.dec(sigB64), msg, b64.dec(pubB64)); } catch { return false; }
}

export const msgSig = { getIdentity, signedString, signMsg, verifyMsg };
