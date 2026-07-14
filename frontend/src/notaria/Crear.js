import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { UploadCloud, FileText, Bitcoin } from 'lucide-react';
import { Nav } from './Nav';
import { useLang } from './i18n';
import { api, sha256Hex, sha256File } from './api';

const CHARS = 'abcdef0123456789';
const scrambleHash = () => Array.from({ length: 64 }, () => CHARS[Math.floor(Math.random() * 16)]).join('');

export default function Crear() {
  const navigate = useNavigate();
  const { t } = useLang();
  const [title, setTitle] = useState('');
  const [kind, setKind] = useState('text');
  const [text, setText] = useState('');
  const [file, setFile] = useState(null);
  const [hash, setHash] = useState('');
  const [scrambling, setScrambling] = useState(false);
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);
  const [payEnabled, setPayEnabled] = useState(false);
  const [payAmount, setPayAmount] = useState('');
  const [payAddress, setPayAddress] = useState('');
  const [payWho, setPayWho] = useState('B');
  const fileRef = useRef(null);
  const scrambleTimer = useRef(null);

  const showHash = (finalHash) => {
    setScrambling(true);
    let ticks = 0;
    clearInterval(scrambleTimer.current);
    scrambleTimer.current = setInterval(() => {
      ticks += 1;
      setHash(scrambleHash());
      if (ticks >= 10) {
        clearInterval(scrambleTimer.current);
        setHash(finalHash);
        setScrambling(false);
      }
    }, 50);
  };

  useEffect(() => () => clearInterval(scrambleTimer.current), []);

  useEffect(() => {
    if (kind !== 'text') return;
    if (!text.trim()) { setHash(''); return; }
    const timer = setTimeout(async () => showHash(await sha256Hex(text)), 350);
    return () => clearTimeout(timer);
  }, [text, kind]); // eslint-disable-line react-hooks/exhaustive-deps

  const onFile = async (f) => {
    if (!f) return;
    setFile(f);
    showHash(await sha256File(f));
  };

  const amountOk = /^\d+(\.\d{1,8})?$/.test(payAmount.trim()) && parseFloat(payAmount) > 0;
  const addrOk = /^(bc1[a-z0-9]{6,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(payAddress.trim());
  const payValid = !payEnabled || (amountOk && addrOk);

  const canSubmit = title.trim() && hash && !scrambling && !busy && payValid
    && ((kind === 'text' && text.trim()) || (kind === 'file' && file));

  const submit = async () => {
    setBusy(true);
    try {
      const payload = {
        title: title.trim(),
        content_hash: hash,
        content_kind: kind,
        content_text: kind === 'text' ? text : null,
        file_name: kind === 'file' ? file.name : null,
        ...(payEnabled && amountOk && addrOk
          ? { pay_amount: payAmount.trim(), pay_address: payAddress.trim(), pay_payer: payWho }
          : {}),
      };
      const a = await api.createAgreement(payload);
      toast.success(t('crear.toastCreated'));
      navigate(`/acuerdo/${a.agreement_id}`);
    } catch (e) {
      toast.error(e.message);
      setBusy(false);
    }
  };

  return (
    <div data-testid="crear-page">
      <Nav />
      <main className="nt-wrap" style={{ padding: '40px 20px 80px', maxWidth: 780 }}>
        <div className="nt-label">{t('crear.kicker')}</div>
        <h1 className="nt-serif" style={{ fontSize: 36, fontWeight: 600, margin: '0 0 28px' }}>{t('crear.title')}</h1>

        <div style={{ marginBottom: 22 }}>
          <label className="nt-label" htmlFor="nt-title">{t('crear.titleLabel')}</label>
          <input id="nt-title" className="nt-input" value={title} maxLength={160}
            onChange={(e) => setTitle(e.target.value)}
            placeholder={t('crear.titlePh')}
            data-testid="create-title-input" />
        </div>

        <div className="nt-tabs" style={{ marginBottom: 18 }}>
          <button className={`nt-tab ${kind === 'text' ? 'on' : ''}`} onClick={() => { setKind('text'); setHash(''); setFile(null); }} data-testid="create-tab-text">
            <FileText size={14} strokeWidth={1.5} /> {t('crear.tabText')}
          </button>
          <button className={`nt-tab ${kind === 'file' ? 'on' : ''}`} onClick={() => { setKind('file'); setHash(''); }} data-testid="create-tab-file">
            <UploadCloud size={14} strokeWidth={1.5} /> {t('crear.tabFile')}
          </button>
        </div>

        {kind === 'text' ? (
          <div style={{ marginBottom: 22 }}>
            <label className="nt-label" htmlFor="nt-text">{t('crear.contentLabel')}</label>
            <textarea id="nt-text" className="nt-textarea" value={text} maxLength={20000}
              onChange={(e) => setText(e.target.value)}
              placeholder={t('crear.textPh')}
              data-testid="create-text-input" />
          </div>
        ) : (
          <div style={{ marginBottom: 22 }}>
            <div
              className={`nt-drop ${drag ? 'drag' : ''}`}
              onClick={() => fileRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files?.[0]); }}
              data-testid="create-file-dropzone"
            >
              <UploadCloud size={26} strokeWidth={1.5} color="var(--muted)" />
              <p style={{ margin: '10px 0 4px', fontWeight: 600, fontSize: 14 }}>
                {file ? file.name : t('crear.dropTitle')}
              </p>
              <p className="nt-note" style={{ margin: 0 }}>{t('crear.dropNote')}</p>
              <input ref={fileRef} type="file" hidden onChange={(e) => onFile(e.target.files?.[0])} data-testid="create-file-input" />
            </div>
          </div>
        )}

        {hash && (
          <div className="nt-card" style={{ marginBottom: 26, padding: 18 }}>
            <div className="nt-label">{t('crear.hashLabel')}</div>
            <div className={scrambling ? 'nt-hashscramble' : 'nt-mono'} style={{ fontSize: 12, color: scrambling ? undefined : 'var(--seal)' }} data-testid="create-hash-preview">
              {hash}
            </div>
          </div>
        )}

        <div className="nt-card" style={{ marginBottom: 22, padding: 18 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontWeight: 600, fontSize: 14 }}>
            <input type="checkbox" checked={payEnabled} onChange={(e) => setPayEnabled(e.target.checked)} data-testid="pay-toggle" />
            <Bitcoin size={15} strokeWidth={1.5} /> {t('pay.toggle')}
          </label>
          {payEnabled && (
            <div style={{ marginTop: 16 }}>
              <label className="nt-label">{t('pay.amount')}</label>
              <input className="nt-input" value={payAmount} onChange={(e) => setPayAmount(e.target.value)} placeholder="0.0005" inputMode="decimal" data-testid="pay-amount-input" />
              <label className="nt-label" style={{ marginTop: 12 }}>{t('pay.address')}</label>
              <input className="nt-input nt-mono" style={{ fontSize: 12 }} value={payAddress} onChange={(e) => setPayAddress(e.target.value)} placeholder="bc1q…" data-testid="pay-address-input" />
              {payAddress && !addrOk && <p className="nt-note" style={{ color: '#c0392b', margin: '6px 0 0' }} data-testid="pay-addr-error">{t('pay.invalidAddr')}</p>}
              <label className="nt-label" style={{ marginTop: 12 }}>{t('pay.who')}</label>
              <div className="nt-tabs" style={{ marginTop: 4 }}>
                <button type="button" className={`nt-tab ${payWho === 'B' ? 'on' : ''}`} onClick={() => setPayWho('B')} data-testid="pay-who-b">{t('pay.bPaysA')}</button>
                <button type="button" className={`nt-tab ${payWho === 'A' ? 'on' : ''}`} onClick={() => setPayWho('A')} data-testid="pay-who-a">{t('pay.aPaysB')}</button>
              </div>
              <p className="nt-note" style={{ margin: '12px 0 0', fontSize: 11 }}>{t('pay.noncustodial')}</p>
            </div>
          )}
        </div>

        <button className="nt-btn nt-btn-seal" disabled={!canSubmit} onClick={submit} data-testid="create-submit-btn" style={{ width: '100%', justifyContent: 'center', padding: '14px 20px' }}>
          {busy ? t('crear.submitting') : t('crear.submit')}
        </button>
        <p className="nt-note" style={{ marginTop: 12, textAlign: 'center' }}>{t('crear.afterNote')}</p>
      </main>
    </div>
  );
}
