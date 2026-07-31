import React, { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { ShieldCheck, Copy, Check, X, Download, Loader2 } from 'lucide-react';
import { useLang } from './i18n';
import { api } from './api';

const trunc = (s, n = 44) => (s && s.length > n ? `${s.slice(0, n)}…` : s || '—');

async function sha256Hex(buf) {
  const d = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

const Copyable = ({ label, value, testid }) => {
  const { t } = useLang();
  return (
    <div className="nt-kv" style={{ alignItems: 'flex-start' }}>
      <span>{label}</span>
      <span style={{ display: 'flex', gap: 8, alignItems: 'center', maxWidth: '72%' }}>
        <span className="nt-mono" style={{ fontSize: 10, wordBreak: 'break-all' }} data-testid={testid}>{trunc(value)}</span>
        <button className="nt-icon-btn" onClick={() => navigator.clipboard.writeText(value).then(() => toast.success(t('verify.copied')))} title={t('verify.copy')}>
          <Copy size={13} strokeWidth={1.5} />
        </button>
      </span>
    </div>
  );
};

export const VerificadorIndependiente = ({ proof, id }) => {
  const { t } = useLang();
  const [hashState, setHashState] = useState('checking');

  useEffect(() => {
    if (window.location.hash === '#verificador') {
      setTimeout(() => document.getElementById('verificador')?.scrollIntoView({ behavior: 'smooth' }), 350);
    }
  }, []);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const res = await fetch(api.proofJsonUrl(id));
        const buf = await res.arrayBuffer();
        const h = await sha256Hex(buf);
        if (alive) setHashState(h === proof.proof_hash ? 'ok' : 'fail');
      } catch {
        if (alive) setHashState('fail');
      }
    })();
    return () => { alive = false; };
  }, [id, proof.proof_hash]);

  const fileBase = `x39-prueba-${id}.json`;
  const pySnippet = (pk, sig, tier) => `pip install pqcrypto
python3 - <<'EOF'
import base64
from pqcrypto.sign import ml_dsa_87 as m
payload = open("${fileBase}", "rb").read()
pk  = base64.b64decode("${pk}")
sig = base64.b64decode("${sig}")
print("${tier} ML-DSA-87 valid:", m.verify(pk, payload, sig))
EOF`;
  const otsCmd = `pip install opentimestamps-client
# guarda ambos archivos con el mismo nombre base:
#   ${fileBase}   y   ${fileBase}.ots
ots verify ${fileBase}.ots
# verificacion soberana (cero terceros) contra TU propio nodo Bitcoin:
# ots --bitcoin-node "http://$(cat ~/.bitcoin/.cookie)@127.0.0.1:8332" verify ${fileBase}.ots`;

  const CmdBlock = ({ title, cmd }) => (
    <div style={{ marginTop: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span className="nt-label">{title}</span>
        <button className="nt-icon-btn" onClick={() => navigator.clipboard.writeText(cmd).then(() => toast.success(t('verify.copied')))} title={t('verify.copy')}>
          <Copy size={13} strokeWidth={1.5} />
        </button>
      </div>
      <pre className="nt-code" data-testid="verify-cmd">{cmd}</pre>
    </div>
  );

  return (
    <div id="verificador" className="nt-card nt-card-pad" style={{ marginTop: 26 }} data-testid="independent-verifier">
      <div className="nt-label" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
        <ShieldCheck size={15} strokeWidth={1.5} /> {t('verify.title')}
      </div>
      <p className="nt-note" style={{ marginTop: 6 }}>{t('verify.intro')}</p>

      <div className="nt-verify-line" data-testid="verify-hash-check" style={{ marginTop: 16 }}>
        {hashState === 'checking' && <Loader2 size={16} className="nt-spin" />}
        {hashState === 'ok' && <Check size={16} color="var(--seal)" />}
        {hashState === 'fail' && <X size={16} color="#c0392b" />}
        <span>{hashState === 'ok' ? t('verify.hashOk') : hashState === 'checking' ? t('verify.checking') : t('verify.hashFail')}</span>
      </div>

      <div className="nt-actions" style={{ marginTop: 14 }}>
        <a className="nt-btn nt-btn-ghost" href={api.proofJsonUrl(id)} data-testid="verify-dl-json"><Download size={13} strokeWidth={1.5} /> {t('verify.dlProof')}</a>
        <a className="nt-btn nt-btn-ghost" href={api.otsUrl(id)} data-testid="verify-dl-ots"><Download size={13} strokeWidth={1.5} /> {t('verify.dlOts')}</a>
      </div>

      {proof.pq && (
        <div style={{ marginTop: 18 }} data-testid="verify-warm">
          <div className="nt-label">{t('verify.warm')}</div>
          <Copyable label={t('verify.pubkey')} value={proof.pq.public_key_b64} testid="verify-warm-pubkey" />
          <Copyable label={t('verify.signature')} value={proof.pq.signature_b64} testid="verify-warm-sig" />
          <CmdBlock title={t('verify.runPy')} cmd={pySnippet(proof.pq.public_key_b64, proof.pq.signature_b64, 'WARM')} />
        </div>
      )}

      <div style={{ marginTop: 18 }} data-testid="verify-cold">
        <div className="nt-label">{t('verify.cold')}</div>
        {proof.cold ? (
          <>
            <Copyable label={t('verify.fp')} value={proof.cold.fingerprint} testid="verify-cold-fp" />
            <Copyable label={t('verify.pubkey')} value={proof.cold.public_key_b64} testid="verify-cold-pubkey" />
            <Copyable label={t('verify.signature')} value={proof.cold.signature_b64} testid="verify-cold-sig" />
            <CmdBlock title={t('verify.runPy')} cmd={pySnippet(proof.cold.public_key_b64, proof.cold.signature_b64, 'COLD')} />
            <a className="nt-btn nt-btn-ghost" style={{ marginTop: 10 }} href="/runbook-ceremonia-cold.pdf"
              target="_blank" rel="noopener noreferrer" data-testid="verify-cold-runbook">
              <Download size={13} strokeWidth={1.5} /> {t('verify.runbook')}
            </a>
          </>
        ) : (
          <p className="nt-note" style={{ marginTop: 4 }} data-testid="verify-no-cold">{t('verify.noCold')}</p>
        )}
      </div>

      <div style={{ marginTop: 18 }}>
        <div className="nt-label">{t('verify.btc')}</div>
        <CmdBlock title={t('verify.runOts')} cmd={otsCmd} />
        <p className="nt-note" style={{ marginTop: 10, fontSize: 13 }} data-testid="verify-sovereign-note">
          {t('verify.sovereign')}{' '}
          <a href="/success_soberano.png" target="_blank" rel="noopener noreferrer"
            style={{ color: 'var(--seal)' }} data-testid="verify-sovereign-proof">
            {t('verify.sovereignProof')}
          </a>
        </p>
      </div>
    </div>
  );
};
