import React, { useRef, useState } from 'react';
import { toast } from 'sonner';
import { CheckCircle2, XCircle, UploadCloud, FileText, Hash, Package } from 'lucide-react';
import { Nav } from './Nav';
import { useLang } from './i18n';
import { api, sha256Hex, sha256File } from './api';
import { verifyBundle } from './bundleVerify';

const HEX64 = /^[0-9a-f]{64}$/;

export default function Verificar() {
  const { t } = useLang();
  const [mode, setMode] = useState('file');
  const [text, setText] = useState('');
  const [hashInput, setHashInput] = useState('');
  const [fileName, setFileName] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [checkedHash, setCheckedHash] = useState('');
  const [drag, setDrag] = useState(false);
  const fileRef = useRef(null);
  const bundleRef = useRef(null);
  const [bundleName, setBundleName] = useState('');
  const [bundleBusy, setBundleBusy] = useState(false);
  const [bundleReport, setBundleReport] = useState(null);
  const [docState, setDocState] = useState(null);

  const onBundle = async (f) => {
    if (!f) return;
    setBundleName(f.name);
    setBundleBusy(true);
    setBundleReport(null);
    setDocState(null);
    try {
      setBundleReport(await verifyBundle(f));
    } catch {
      toast.error(t('ver.bundleErr'));
    } finally {
      setBundleBusy(false);
    }
  };

  const onDocLink = async (f) => {
    if (!f || !bundleReport?.proof) return;
    setDocState((await sha256File(f)) === bundleReport.proof.content_hash ? 'ok' : 'bad');
  };

  const check = async (h) => {
    setBusy(true);
    setResult(null);
    try {
      setCheckedHash(h);
      const r = await api.verify(h);
      setResult(r);
    } catch (e) {
      toast.error(e.message);
    } finally {
      setBusy(false);
    }
  };

  const onFile = async (f) => {
    if (!f) return;
    setFileName(f.name);
    check(await sha256File(f));
  };

  const submit = async () => {
    if (mode === 'text') {
      if (!text.trim()) return;
      check(await sha256Hex(text));
    } else if (mode === 'hash') {
      const h = hashInput.trim().toLowerCase();
      if (!HEX64.test(h)) { toast.error(t('ver.invalidHash')); return; }
      check(h);
    }
  };

  return (
    <div data-testid="verificar-page">
      <Nav />
      <main className="nt-wrap" style={{ padding: '40px 20px 80px', maxWidth: 720 }}>
        <div className="nt-label">{t('ver.kicker')}</div>
        <h1 className="nt-serif" style={{ fontSize: 36, fontWeight: 600, margin: '0 0 8px' }}>{t('ver.title')}</h1>
        <p className="nt-note" style={{ margin: '0 0 26px', fontSize: 14 }}>{t('ver.sub')}</p>

        <div className="nt-tabs" style={{ marginBottom: 18 }}>
          <button className={`nt-tab ${mode === 'file' ? 'on' : ''}`} onClick={() => { setMode('file'); setResult(null); }} data-testid="verify-tab-file"><UploadCloud size={14} strokeWidth={1.5} /> {t('ver.tabFile')}</button>
          <button className={`nt-tab ${mode === 'text' ? 'on' : ''}`} onClick={() => { setMode('text'); setResult(null); }} data-testid="verify-tab-text"><FileText size={14} strokeWidth={1.5} /> {t('ver.tabText')}</button>
          <button className={`nt-tab ${mode === 'hash' ? 'on' : ''}`} onClick={() => { setMode('hash'); setResult(null); }} data-testid="verify-tab-hash"><Hash size={14} strokeWidth={1.5} /> {t('ver.tabHash')}</button>
          <button className={`nt-tab ${mode === 'bundle' ? 'on' : ''}`} onClick={() => { setMode('bundle'); setResult(null); }} data-testid="verify-tab-bundle"><Package size={14} strokeWidth={1.5} /> {t('ver.tabBundle')}</button>
        </div>

        {mode === 'file' && (
          <div
            className={`nt-drop ${drag ? 'drag' : ''}`}
            onClick={() => fileRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files?.[0]); }}
            data-testid="verify-dropzone"
          >
            <UploadCloud size={26} strokeWidth={1.5} color="var(--muted)" />
            <p style={{ margin: '10px 0 4px', fontWeight: 600, fontSize: 14 }}>{fileName || t('ver.dropTitle')}</p>
            <p className="nt-note" style={{ margin: 0 }}>{t('ver.dropNote')}</p>
            <input ref={fileRef} type="file" hidden onChange={(e) => onFile(e.target.files?.[0])} data-testid="verify-file-input" />
          </div>
        )}

        {mode === 'text' && (
          <>
            <textarea className="nt-textarea" value={text} onChange={(e) => setText(e.target.value)}
              placeholder={t('ver.textPh')} data-testid="verify-text-input" />
            <button className="nt-btn nt-btn-primary" style={{ marginTop: 14 }} onClick={submit} disabled={busy || !text.trim()} data-testid="verify-text-submit">
              {busy ? t('ver.verifying') : t('ver.verifyTextBtn')}
            </button>
          </>
        )}

        {mode === 'hash' && (
          <>
            <input className="nt-input nt-mono" value={hashInput} onChange={(e) => setHashInput(e.target.value)}
              placeholder={t('ver.hashPh')} data-testid="verify-hash-input" />
            <button className="nt-btn nt-btn-primary" style={{ marginTop: 14 }} onClick={submit} disabled={busy || !hashInput.trim()} data-testid="verify-hash-submit">
              {busy ? t('ver.verifying') : t('ver.verifyHashBtn')}
            </button>
          </>
        )}

        {mode === 'bundle' && (
          <>
            <div
              className={`nt-drop ${drag ? 'drag' : ''}`}
              onClick={() => bundleRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); onBundle(e.dataTransfer.files?.[0]); }}
              data-testid="verify-bundle-dropzone"
            >
              <Package size={26} strokeWidth={1.5} color="var(--muted)" />
              <p style={{ margin: '10px 0 4px', fontWeight: 600, fontSize: 14 }}>{bundleName || t('ver.bundleDrop')}</p>
              <p className="nt-note" style={{ margin: 0 }}>{t('ver.bundleNote')}</p>
              <input ref={bundleRef} type="file" accept=".zip" hidden onChange={(e) => onBundle(e.target.files?.[0])} data-testid="verify-bundle-input" />
            </div>
            {bundleBusy && <p className="nt-note nt-mono" style={{ marginTop: 14 }}>{t('ver.bverifying')}</p>}
            {bundleReport && (
              <div className="nt-card nt-card-pad" style={{ marginTop: 28, borderColor: bundleReport.verdict === 'fail' ? 'var(--error)' : 'var(--seal)' }} data-testid="verify-bundle-result">
                <h2 className="nt-serif" style={{ fontSize: 22, fontWeight: 600, margin: '0 0 16px', color: bundleReport.verdict === 'fail' ? 'var(--error)' : 'var(--seal)' }} data-testid="verify-bundle-verdict">
                  {t(`ver.bverdict.${bundleReport.verdict}`)}
                </h2>
                {bundleReport.checks.map((c) => (
                  <div className="nt-kv" key={c.id} data-testid={`verify-bundle-${c.id}`}>
                    <span>
                      {t(`ver.bcheck.${c.id}`)}
                      {c.count != null ? ` · ${c.count}` : ''}
                      {c.signed != null ? ` · ${c.signed}/${c.total}` : ''}
                    </span>
                    <span className="nt-mono" style={{ color: c.ok ? 'var(--seal)' : 'var(--error)', fontWeight: 700 }}>{c.ok ? '✓' : '✗'}</span>
                  </div>
                ))}
                {bundleReport.noCold && (
                  <div className="nt-kv"><span>{t('ver.bcheck.mldsa_cold')}</span><span className="nt-mono" style={{ color: 'var(--muted)' }} data-testid="verify-bundle-cold-absent">—</span></div>
                )}
                {bundleReport.proof && (
                  <>
                    <div className="nt-kv"><span>ID</span><span className="nt-mono">{bundleReport.proof.agreement_id} · {bundleReport.proof.v}</span></div>
                    <div className="nt-kv"><span>content_hash</span><span className="nt-mono" style={{ fontSize: 10 }}>{bundleReport.proof.content_hash}</span></div>
                  </>
                )}
                <p className="nt-note" style={{ margin: '14px 0 0', fontSize: 11 }} data-testid="verify-bundle-ots-note">
                  {t('ver.botsNote')}{bundleReport.otsBytes ? ` (${bundleReport.otsBytes} B)` : ''}
                </p>
                {bundleReport.proof && (
                  <div style={{ marginTop: 18 }}>
                    <div className="nt-label">{t('ver.bdocTitle')}</div>
                    <p className="nt-note" style={{ margin: '4px 0 8px', fontSize: 11 }}>{t('ver.bdocNote')}</p>
                    <input type="file" onChange={(e) => onDocLink(e.target.files?.[0])} data-testid="verify-bundle-doc-input" style={{ fontSize: 13 }} />
                    {docState && (
                      <p style={{ margin: '10px 0 0', fontWeight: 600, fontSize: 13, color: docState === 'ok' ? 'var(--seal)' : 'var(--error)' }} data-testid="verify-bundle-doc-result">
                        {docState === 'ok' ? `✓ ${t('ver.bdocOk')}` : `✗ ${t('ver.bdocBad')}`}
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {result && (
          <div className="nt-card nt-card-pad" style={{ marginTop: 28, borderColor: result.found ? 'var(--seal)' : 'var(--error)' }} data-testid="verify-result">
            {result.found ? (
              <div className="nt-verify-ok">
                <CheckCircle2 size={44} strokeWidth={1.5} className="check" />
                <h2 className="nt-serif" style={{ fontSize: 26, fontWeight: 600, margin: '10px 0 4px' }}>{t('ver.foundTitle')}</h2>
                <p className="nt-note" style={{ margin: '0 0 18px' }}>
                  {t('ver.matchedBy')} {result.matched === 'content' ? t('ver.matchedContent') : t('ver.matchedProof')}.
                </p>
                <div style={{ textAlign: 'left' }}>
                  <div className="nt-kv"><span>{t('ver.fTitle')}</span><span>{result.title}</span></div>
                  <div className="nt-kv"><span>{t('ag.sealedAt')}</span><span className="nt-mono">{result.sealed_at}</span></div>
                  <div className="nt-kv"><span>{t('ver.anchor')}</span>
                    <span className="nt-mono" data-testid="verify-ots-status">
                      {result.ots_status === 'anchored_btc'
                        ? <a style={{ color: 'var(--seal)', textDecoration: 'underline' }} href={`https://mempool.space/block/${result.btc_block}`} target="_blank" rel="noreferrer" data-testid="verify-block-link">{t('ag.badgeConfirmedIn')}{result.btc_block} →</a>
                        : t('ver.pendingConf')}
                    </span>
                  </div>
                  <div className="nt-kv"><span>{t('ver.contentHash')}</span><span className="nt-mono" style={{ fontSize: 10 }}>{result.content_hash}</span></div>
                  <div className="nt-kv"><span>{t('ag.proofHash')}</span><span className="nt-mono" style={{ fontSize: 10 }}>{result.proof_hash}</span></div>
                </div>
                <div className="nt-actions" style={{ marginTop: 18, justifyContent: 'center' }}>
                  <a className="nt-btn nt-btn-ghost" href={api.certUrl(result.agreement_id)} target="_blank" rel="noreferrer" data-testid="verify-cert-btn">{t('ag.certPdf')}</a>
                  <a className="nt-btn nt-btn-ghost" href={api.otsUrl(result.agreement_id)} data-testid="verify-ots-btn">{t('ag.otsProof')}</a>
                </div>
              </div>
            ) : (
              <div className="nt-verify-bad" style={{ textAlign: 'center' }}>
                <XCircle size={44} strokeWidth={1.5} className="cross" />
                <h2 className="nt-serif" style={{ fontSize: 26, fontWeight: 600, margin: '10px 0 4px', color: 'var(--error)' }}>{t('ver.notFoundTitle')}</h2>
                <p className="nt-note" style={{ margin: 0 }}>{t('ver.notFoundBody')}</p>
                <div className="nt-mono" style={{ fontSize: 10, marginTop: 12, color: 'var(--muted)' }}>{checkedHash}</div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
