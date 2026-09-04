// id.js — Identidad por llave (Ed25519). Sin correo, sin terceros: tu llave ES tu identidad.
// La llave privada vive SOLO en este dispositivo (localStorage nt_id_v1) y en la copia
// de seguridad que guarda el usuario. El servidor solo conoce la publica.
// Copia de seguridad: bloque de texto "X39KEY-v1:<base64(sk)>".
import { ed25519 } from '@noble/curves/ed25519.js';
import { api } from './api';

const SLOT = 'nt_id_v1';
const b64enc = (u8) => btoa(String.fromCharCode(...u8));
const b64dec = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function loadSk() {
  try {
    const saved = JSON.parse(localStorage.getItem(SLOT) || 'null');
    if (saved?.sk) {
      const sk = b64dec(saved.sk);
      if (sk.length === 32) return sk;
    }
  } catch { /* corrupta: se trata como inexistente */ }
  return null;
}

function saveSk(sk) {
  localStorage.setItem(SLOT, JSON.stringify({
    sk: b64enc(sk), alg: 'Ed25519', v: 1, created_at: new Date().toISOString(),
  }));
}

export function hasKey() { return loadSk() !== null; }

export function createKey() {
  if (hasKey()) throw new Error('Ya existe una llave en este dispositivo');
  const sk = crypto.getRandomValues(new Uint8Array(32));
  saveSk(sk);
  return getPubB64();
}

export function getPubB64() {
  const sk = loadSk();
  if (!sk) return null;
  return b64enc(ed25519.getPublicKey(sk));
}

// Bloque exportable para la copia de seguridad. CONTIENE LA LLAVE PRIVADA.
export function exportBlock() {
  const sk = loadSk();
  if (!sk) return null;
  return `X39KEY-v1:${b64enc(sk)}`;
}

export function importBlock(text) {
  const clean = (text || '').trim();
  if (!clean.startsWith('X39KEY-v1:')) throw new Error('Formato de llave no reconocido');
  let sk;
  try { sk = b64dec(clean.slice('X39KEY-v1:'.length).trim()); }
  catch { throw new Error('Base64 invalido'); }
  if (sk.length !== 32) throw new Error('La llave debe tener 32 bytes');
  saveSk(sk);
  return getPubB64();
}

export function wipeKey() { localStorage.removeItem(SLOT); }

// Login por reto: pide nonce, firma EXACTAMENTE x39auth:v1:<nonce> y verifica.
// Nunca firmamos una cadena arbitraria del servidor.
export async function login() {
  const sk = loadSk();
  if (!sk) throw new Error('No hay llave en este dispositivo');
  const pub_b64 = b64enc(ed25519.getPublicKey(sk));
  const ch = await api.keyChallenge(pub_b64);
  if (!ch?.nonce || ch.payload !== `x39auth:v1:${ch.nonce}`) {
    throw new Error('Reto inesperado del servidor');
  }
  const sig_b64 = b64enc(ed25519.sign(new TextEncoder().encode(ch.payload), sk));
  return api.keyVerify(pub_b64, ch.nonce, sig_b64);
}

// Identidad corta derivada de la publica (coincide con la del servidor: key:sha256(pub)[:16]).
export async function shortId() {
  const sk = loadSk();
  if (!sk) return null;
  const pub = ed25519.getPublicKey(sk);
  const digest = await crypto.subtle.digest('SHA-256', pub);
  const hex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return `key:${hex.slice(0, 16)}`;
}
