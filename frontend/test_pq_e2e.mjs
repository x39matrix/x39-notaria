// Test E2E del protocolo hibrido X-Wing contra el backend real (misma lib que el navegador).
import { XWing } from '@noble/post-quantum/hybrid.js';
import { webcrypto as wc } from 'node:crypto';

const API = process.env.API_URL;
const BASE = `${API}/api/notaria`;
const TOK = { A: 'test_session_qa_a', B: 'test_session_qa_b', C: 'test_session_qa_c' };
const b64e = (u8) => Buffer.from(u8).toString('base64');
const b64d = (s) => new Uint8Array(Buffer.from(s, 'base64'));

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; console.log(`${cond ? 'PASS' : 'FAIL'} - ${name}`); };

async function req(who, path, { method = 'GET', body, csrf } = {}) {
  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${TOK[who]}` };
  if (csrf) headers['X-CSRF-Token'] = csrf;
  const r = await fetch(`${BASE}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, data: await r.json().catch(() => ({})) };
}

const csrfOf = async (who) => (await req(who, '/auth/me')).data.csrf_token;

async function deriveKey(aid, ss) {
  const te = new TextEncoder();
  const ikm = await wc.subtle.importKey('raw', ss, 'HKDF', false, ['deriveKey']);
  return wc.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: te.encode('x39-notaria-e2e|XWING-MLKEM768-X25519-v2'), info: te.encode(`aid:${aid}`) },
    ikm, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

const main = async () => {
  const [csrfA, csrfB] = [await csrfOf('A'), await csrfOf('B')];

  // 1. A crea el acuerdo, B se une
  const create = await req('A', '/agreements', { method: 'POST', csrf: csrfA, body: {
    title: 'QA PQ hybrid', content_hash: 'a'.repeat(64), content_kind: 'text', content_text: 'test pq' } });
  ok('A crea acuerdo (200)', create.status === 200);
  const aid = create.data.agreement_id;
  const inv = create.data.invite_token;
  const join = await req('B', `/agreements/${aid}/join`, { method: 'POST', csrf: csrfB, body: { invite_token: inv } });
  ok('B se une (200)', join.status === 200);

  // 2. Handshake X-Wing: A keygen + publica pub
  const seedA = wc.getRandomValues(new Uint8Array(32));
  const keysA = XWing.keygen(seedA);
  const pubPost = await req('A', `/agreements/${aid}/e2e_pq_key`, { method: 'POST', csrf: csrfA, body: { xwing_pub_b64: b64e(keysA.publicKey) } });
  ok('A publica xwing_pub (200)', pubPost.status === 200 && pubPost.data.suite === 'XWING-MLKEM768-X25519-v2');

  // negativos: rol equivocado y tamano invalido
  const wrongRole = await req('B', `/agreements/${aid}/e2e_pq_key`, { method: 'POST', csrf: csrfB, body: { xwing_pub_b64: b64e(keysA.publicKey) } });
  ok('B NO puede publicar pub (400)', wrongRole.status === 400);
  const badSize = await req('A', `/agreements/${aid}/e2e_pq_key`, { method: 'POST', csrf: csrfA, body: { xwing_pub_b64: b64e(new Uint8Array(100)) } });
  ok('pub de 100 B rechazada (400)', badSize.status === 400);
  const wrongRole2 = await req('A', `/agreements/${aid}/e2e_pq_key`, { method: 'POST', csrf: csrfA, body: { xwing_ct_b64: b64e(new Uint8Array(1120)) } });
  ok('A NO puede publicar ct (400)', wrongRole2.status === 400);

  // 3. B lee la pub, encapsula, publica ct
  const keysForB = await req('B', `/agreements/${aid}/e2e_pq_keys`);
  ok('B lee pub de A', keysForB.data.A?.xwing_pub_b64 === b64e(keysA.publicKey));
  const { cipherText, sharedSecret: ssB } = XWing.encapsulate(b64d(keysForB.data.A.xwing_pub_b64));
  const ctPost = await req('B', `/agreements/${aid}/e2e_pq_key`, { method: 'POST', csrf: csrfB, body: { xwing_ct_b64: b64e(cipherText) } });
  ok('B publica xwing_ct (200)', ctPost.status === 200);

  // 4. A lee el ct, decapsula: secretos identicos en ambos extremos
  const keysForA = await req('A', `/agreements/${aid}/e2e_pq_keys`);
  const ssA = XWing.decapsulate(b64d(keysForA.data.B.xwing_ct_b64), keysA.secretKey);
  ok('shared secret identico (A==B)', Buffer.from(ssA).equals(Buffer.from(ssB)));

  // 5. HKDF -> AES-GCM: A cifra, B descifra (y viceversa)
  const kA = await deriveKey(aid, ssA);
  const kB = await deriveKey(aid, ssB);
  const iv = wc.getRandomValues(new Uint8Array(12));
  const ct1 = await wc.subtle.encrypt({ name: 'AES-GCM', iv }, kA, new TextEncoder().encode('hola desde A'));
  const pt1 = new TextDecoder().decode(await wc.subtle.decrypt({ name: 'AES-GCM', iv }, kB, ct1));
  ok('A cifra -> B descifra', pt1 === 'hola desde A');
  const iv2 = wc.getRandomValues(new Uint8Array(12));
  const ct2 = await wc.subtle.encrypt({ name: 'AES-GCM', iv: iv2 }, kB, new TextEncoder().encode('hola desde B'));
  const pt2 = new TextDecoder().decode(await wc.subtle.decrypt({ name: 'AES-GCM', iv: iv2 }, kA, ct2));
  ok('B cifra -> A descifra', pt2 === 'hola desde B');

  // 6. mensaje cifrado por el canal normal + tercero sin acceso
  const msg = await req('A', `/agreements/${aid}/messages`, { method: 'POST', csrf: csrfA, body: { ct: b64e(new Uint8Array(ct1)), iv: b64e(iv) } });
  ok('mensaje cifrado aceptado (200)', msg.status === 200);
  const third = await req('C', `/agreements/${aid}/e2e_pq_keys`);
  ok('tercero sin acceso (403)', third.status === 403);

  // 7. ct alterado -> decapsulacion da secreto DISTINTO (implicit rejection FIPS-203)
  const tampered = Uint8Array.from(cipherText); tampered[0] ^= 0xff;
  const ssTampered = XWing.decapsulate(tampered, keysA.secretKey);
  ok('ct alterado NO reproduce el secreto', !Buffer.from(ssTampered).equals(Buffer.from(ssB)));

  console.log(`\n${pass} PASS / ${fail} FAIL`);
  process.exit(fail ? 1 : 0);
};
main().catch((e) => { console.error('ERROR', e); process.exit(1); });
