// Cadena de hashes enlazada del chat (X39-NOTARIA-2). Replica EXACTA de _build_chat_chain
// en backend/notaria.py: content_hash = sha256(utf8(ct_b64 + iv_b64)) (strings, NO binario),
// msg_hash = sha256(utf8(`${prev}:${content_hash}:${ts}:${role}`)), role A/B por sender==party_a.

const enc = new TextEncoder();

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function computeChainTip(messages, partyA) {
  let prev = '0'.repeat(64);
  for (const m of messages) {
    const body = ((m.ct || '') + (m.iv || '')) || (m.text || '');
    const contentHash = await sha256Hex(body);
    const role = m.sender === partyA ? 'A' : 'B';
    prev = await sha256Hex(`${prev}:${contentHash}:${m.ts || ''}:${role}`);
  }
  return { tip: prev, count: messages.length };
}

// Verificacion offline de chat_chain.json (bundle): recomputa msg_hash + continuidad + tip==root.
export async function verifyChainEntries(entries, root) {
  let prev = '0'.repeat(64);
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.prev_hash !== prev) return { ok: false, index: i, reason: 'prev_hash' };
    const h = await sha256Hex(`${prev}:${e.content_hash}:${e.ts || ''}:${e.role}`);
    if (h !== e.msg_hash) return { ok: false, index: i, reason: 'msg_hash' };
    prev = h;
  }
  return prev === root ? { ok: true } : { ok: false, index: -1, reason: 'tip' };
}
