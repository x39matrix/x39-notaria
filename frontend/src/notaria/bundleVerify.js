// Verificador universal de bundles de evidencia — 100% client-side, cero red.
// Espejo del verificador de referencia verify_bundle.py:
//   integridad, consistencia, cadena de chat (v2/v3), firmas Ed25519 por mensaje (v3),
//   firmas ML-DSA-87 COLD/WARM (noble, FIPS-204). El ancla OTS NO se verifica aqui
//   (requiere nodo Bitcoin): se informa honestamente, nunca se pinta verde sin verificar.
import JSZip from 'jszip';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256Hex } from './api';
import { verifyChainEntries } from './chain';

const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function verifyBundle(file) {
  const report = { checks: [], proof: null, otsBytes: 0, noCold: false, verdict: 'fail' };
  const add = (id, ok, meta = {}) => report.checks.push({ id, ok, ...meta });
  let zip;
  try {
    zip = await JSZip.loadAsync(file);
  } catch {
    add('files', false);
    return report;
  }
  const proofFile = zip.file('proof.json');
  const sigsFile = zip.file('signatures.json');
  if (!proofFile || !sigsFile) { add('files', false); return report; }
  const proofBytes = await proofFile.async('uint8array');
  let proof, sigs;
  try {
    proof = JSON.parse(new TextDecoder().decode(proofBytes));
    sigs = JSON.parse(await sigsFile.async('string'));
  } catch {
    add('files', false);
    return report;
  }
  report.proof = proof;

  // 1. Integridad: sha256(proof.json) == signatures.proof_hash
  const ph = await sha256Hex(proofBytes);
  add('integrity', ph === sigs.proof_hash, { hash: ph });

  // 2. Consistencia de campos cruzados
  const consistent = ['agreement_id', 'content_hash', 'sealed_at']
    .every((f) => proof[f] == null || sigs[f] == null || proof[f] === sigs[f]);
  add('consistency', consistent);

  // 3. Cadena de chat (v2/v3)
  if (proof.chat_merkle_root) {
    const chainFile = zip.file('chat_chain.json');
    if (!chainFile) {
      add('chain', false, { count: 0 });
    } else {
      try {
        const entries = JSON.parse(await chainFile.async('string')).entries || [];
        const r = await verifyChainEntries(entries, proof.chat_merkle_root);
        add('chain', r.ok, { count: entries.length, index: r.index });
        // 4. Firmas Ed25519 por mensaje (v3)
        if (proof.msg_sigs) {
          const keys = proof.sig_keys || {};
          let okCount = 0, valid = true;
          for (const e of entries) {
            if (!e.sig_b64) continue;
            const pk = keys[e.role];
            const msg = new TextEncoder().encode(`x39msg:v3:${proof.agreement_id}:${e.content_hash}:${e.cts}`);
            let good = false;
            try { good = !!pk && ed25519.verify(b64d(e.sig_b64), msg, b64d(pk)); } catch { good = false; }
            if (good) okCount += 1; else valid = false;
          }
          add('msgsigs', valid && okCount === proof.msg_sigs.signed,
            { signed: okCount, total: proof.msg_sigs.total });
        }
      } catch {
        add('chain', false, { count: 0 });
      }
    }
  }

  // 5. Firmas ML-DSA-87 (COLD soberana / WARM historica). Ausencia de COLD = aviso, no fallo:
  // la co-firma se aplica post-sellado y su ausencia no es detectable criptograficamente.
  for (const tier of ['cold', 'warm']) {
    const blk = sigs[tier];
    if (!blk) { if (tier === 'cold') report.noCold = true; continue; }
    let ok = false, fpOk = true;
    try {
      const pk = b64d(blk.public_key_b64);
      ok = ml_dsa87.verify(b64d(blk.signature_b64), proofBytes, pk);
      if (blk.fingerprint) fpOk = (await sha256Hex(pk)) === blk.fingerprint;
    } catch { ok = false; }
    add(`mldsa_${tier}`, ok && fpOk, { fp: blk.fingerprint });
  }

  const otsFile = zip.file('proof.json.ots');
  if (otsFile) report.otsBytes = (await otsFile.async('uint8array')).length;

  const allOk = report.checks.length > 0 && report.checks.every((c) => c.ok);
  report.verdict = allOk ? (report.noCold ? 'valid_no_cold' : 'valid') : 'fail';
  return report;
}
