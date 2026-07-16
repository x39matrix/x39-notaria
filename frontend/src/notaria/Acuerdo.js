import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import { Copy, Send, RefreshCw, Download, FileCheck2, Lock, ExternalLink, Bitcoin } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { Nav } from './Nav';
import { useAuth } from './NotariaApp';
import { useLang } from './i18n';
import { api } from './api';
import { e2e } from './e2e';
import { e2e2 } from './e2e2';

const OtsBadge = ({ ots, status, t }) => {
  if (status !== 'sealed') return <span className="nt-badge nt-badge-pending" data-testid="agreement-status-badge">{t('ag.badgePending')}</span>;
  if (ots?.status === 'anchored_btc') {
    return <span className="nt-badge nt-badge-sealed" data-testid="agreement-status-badge">{t('ag.badgeConfirmedIn')}{ots.btc_block}</span>;
  }
  return <span className="nt-badge nt-badge-draft" data-testid="agreement-status-badge">{t('ag.badgeSealedPendingBtc')}</span>;
};

export default function Acuerdo() {
  const { id } = useParams();
  const { user } = useAuth();
  const { lang, t } = useLang();
  const [ag, setAg] = useState(null);
  const [msgs, setMsgs] = useState([]);
  const [frozen, setFrozen] = useState(false);
  const [text, setText] = useState('');
  const [signing, setSigning] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [payStatus, setPayStatus] = useState(null);
  const [payChecking, setPayChecking] = useState(false);
  const [error, setError] = useState(null);
  const [sharedKey, setSharedKey] = useState(null);
  const [pqActive, setPqActive] = useState(false);
  const [view, setView] = useState([]);
  const identityRef = useRef(null);
  const pqIdRef = useRef(null);
  const chatEndRef = useRef(null);
  const sealed = ag?.status === 'sealed';
  const locale = { es: 'es-ES', en: 'en-GB', zh: 'zh-CN', ja: 'ja-JP' }[lang] || 'es-ES';

  const load = useCallback(async () => {
    try {
      const [a, m] = await Promise.all([api.getAgreement(id), api.getMessages(id)]);
      setAg(a);
      setMsgs(m.messages);
      setFrozen(m.frozen);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  // Al cambiar de acuerdo, resetea el secreto compartido para re-derivarlo con la contraparte correcta.
  useEffect(() => { setSharedKey(null); setPqActive(false); setView([]); }, [id]);

  useEffect(() => {
    if (sealed) return;
    const timer = setInterval(load, 4000);
    return () => clearInterval(timer);
  }, [sealed, load]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [view.length]);

  // E2E v2: handshake hibrido post-cuantico X-Wing (ML-KEM-768 + X25519, IETF).
  // A publica su pubkey; B encapsula y publica el ct; ambos derivan AES-256-GCM via HKDF.
  // Hilos con claves P-256 ya establecidas por ambas partes siguen en v1 (sin downgrade de v2 a v1).
  useEffect(() => {
    if (!user?.email || !ag?.my_role || sealed || sharedKey) return;
    let stop = false;
    const setup = async () => {
      try {
        const pq = await api.getE2EPQKeys(id).catch(() => null);
        if (stop || !pq) return;
        if (!pq.A && !pq.B) {
          const legacy = await api.getE2EKeys(id).catch(() => null);
          if (stop) return;
          if (legacy?.A && legacy?.B) {
            if (!identityRef.current) {
              identityRef.current = await e2e.getIdentity(user.email);
              await api.publishE2EKey(id, identityRef.current.pubJwk).catch(() => {});
            }
            const peerJwk = legacy[ag.my_role === 'A' ? 'B' : 'A'];
            if (peerJwk) {
              const sk = await e2e.deriveKey(identityRef.current.privKey, peerJwk);
              if (!stop) { setPqActive(false); setSharedKey(sk); }
            }
            return;
          }
        }
        if (ag.my_role === 'A') {
          if (!pqIdRef.current) pqIdRef.current = e2e2.getIdentityA(user.email);
          const me = pqIdRef.current;
          if ((pq.A?.xwing_pub_b64 || null) !== me.pubB64) {
            await api.publishE2EPQKey(id, { xwing_pub_b64: me.pubB64 }).catch(() => {});
            return;
          }
          if (pq.B?.xwing_ct_b64) {
            const ss = e2e2.decapsulate(me, pq.B.xwing_ct_b64);
            const key = await e2e2.deriveKey(id, ss);
            if (!stop) { setPqActive(true); setSharedKey(key); }
          }
        } else if (pq.A?.xwing_pub_b64) {
          const enc = e2e2.encapsulate(id, user.email, pq.A.xwing_pub_b64, pq.B?.xwing_ct_b64 || null);
          if ((pq.B?.xwing_ct_b64 || null) !== enc.ctB64) {
            await api.publishE2EPQKey(id, { xwing_ct_b64: enc.ctB64 }).catch(() => {});
          }
          const key = await e2e2.deriveKey(id, enc.ss);
          if (!stop) { setPqActive(true); setSharedKey(key); }
        }
      } catch (e) { console.warn('e2e handshake:', e?.message); /* el chat muestra estado de espera hasta derivar */ }
    };
    setup();
    const timer = setInterval(setup, 4000);
    return () => { stop = true; clearInterval(timer); };
  }, [user?.email, ag?.my_role, id, sealed, sharedKey]);

  // Descifra los mensajes para mostrarlos (los antiguos en claro se muestran tal cual).
  useEffect(() => {
    let stop = false;
    (async () => {
      const out = [];
      for (const m of msgs) {
        if (m.text != null) { out.push({ ...m, text: m.text }); continue; }
        if (m.ct && sharedKey) {
          try { out.push({ ...m, text: await e2e.decryptMsg(sharedKey, m.ct, m.iv) }); }
          catch { out.push({ ...m, locked: true }); }
        } else {
          out.push({ ...m, locked: true });
        }
      }
      if (!stop) setView(out);
    })();
    return () => { stop = true; };
  }, [msgs, sharedKey]);

  const send = async () => {
    const v = text.trim();
    if (!v) return;
    if (!sharedKey) { toast.error(t('ag.e2eWaiting')); return; }
    setText('');
    try {
      const { ct, iv } = await e2e.encryptMsg(sharedKey, v);
      const m = await api.postMessage(id, ct, iv);
      setMsgs((prev) => [...prev, m]);
    } catch (e) {
      setText(v);
      toast.error(e.message);
    }
  };

  const sign = async () => {
    setSigning(true);
    try {
      const a = await api.sign(id);
      setAg(a);
      if (a.status === 'sealed') {
        toast.success(t('ag.toastSealed'));
        load();
      } else {
        toast.success(t('ag.toastSigned'));
      }
    } catch (e) {
      toast.error(e.message);
    } finally {
      setSigning(false);
    }
  };

  const refreshOts = async () => {
    setRefreshing(true);
    try {
      const st = await api.refreshOts(id);
      setAg((prev) => ({ ...prev, ots: { ...prev.ots, ...st } }));
      if (st.status === 'anchored_btc') toast.success(`${t('ag.badgeConfirmedIn')}${st.btc_block}`);
      else toast(t('ag.toastStillPending'));
    } catch (e) {
      toast.error(e.message);
    } finally {
      setRefreshing(false);
    }
  };

  const copy = (v, msg) => {
    navigator.clipboard.writeText(v).then(() => toast.success(msg));
  };

  const checkPay = async () => {
    setPayChecking(true);
    try {
      const st = await api.paymentStatus(id);
      setPayStatus(st);
    } catch (e) {
      toast.error(e.message);
    } finally {
      setPayChecking(false);
    }
  };

  if (error) {
    return (
      <div><Nav />
        <main className="nt-wrap nt-center"><div className="nt-card nt-card-pad" style={{ textAlign: 'center' }}>
          <p className="nt-serif" style={{ fontSize: 22 }}>{error}</p>
          <Link to="/panel" className="nt-btn nt-btn-ghost">{t('common.backToPanel')}</Link>
        </div></main>
      </div>
    );
  }
  if (!ag) return <div><Nav /><div className="nt-center"><div className="nt-note nt-mono">{t('common.loading')}</div></div></div>;

  const iSigned = ag.my_role && ag.signatures?.[ag.my_role];
  const inviteUrl = ag.invite_token ? `${window.location.origin}/unirse/${id}?t=${ag.invite_token}` : null;

  return (
    <div data-testid="acuerdo-page">
      <Nav />
      <main className="nt-wrap" style={{ padding: '36px 20px 80px' }}>
        <div style={{ marginBottom: 24 }}>
          <div className="nt-label">{t('ag.kicker')} · {ag.agreement_id}</div>
          <h1 className="nt-serif" style={{ fontSize: 32, fontWeight: 600, margin: '0 0 10px' }} data-testid="agreement-title">{ag.title}</h1>
          <OtsBadge ots={ag.ots} status={ag.status} t={t} />
        </div>

        <div className="nt-split">
          <div>
            <div className="nt-doc" style={{ marginBottom: 20 }}>
              <div className="nt-label">{ag.content_kind === 'text' ? t('ag.contentLabel') : t('ag.fileLabel')}</div>
              {ag.content_kind === 'text' ? (
                <div className="nt-doc-content" data-testid="agreement-content">{ag.content_text}</div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }} data-testid="agreement-content">
                  <FileCheck2 size={18} strokeWidth={1.5} color="var(--seal)" />
                  <span style={{ fontWeight: 600 }}>{ag.file_name || 'file'}</span>
                  <span className="nt-note">{t('ag.fileNote')}</span>
                </div>
              )}
              <hr className="nt-hr" />
              <div className="nt-label">{t('ag.hashLabel')}</div>
              <div className="nt-mono" style={{ fontSize: 11 }} data-testid="agreement-content-hash">{ag.content_hash}</div>
            </div>

            <div className="nt-card" style={{ marginBottom: 20 }}>
              <div className="nt-label">{t('ag.parties')}</div>
              <div className="nt-kv"><span>{t('ag.partyA')}</span><span className="nt-mono">{ag.party_a} · {ag.signatures?.A ? t('ag.signed') : t('ag.notSigned')}</span></div>
              <div className="nt-kv"><span>{t('ag.partyB')}</span><span className="nt-mono">{ag.party_b ? `${ag.party_b} · ${ag.signatures?.B ? t('ag.signed') : t('ag.notSigned')}` : t('ag.pendingJoin')}</span></div>
            </div>

            {ag.payment && (
              <div className="nt-card" style={{ marginBottom: 20, borderColor: 'var(--seal)' }} data-testid="payment-section">
                <div className="nt-label" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Bitcoin size={13} strokeWidth={1.5} /> {t('pay.terms')}
                </div>
                <div className="nt-kv"><span>{t('pay.amountLabel')}</span><span className="nt-mono" data-testid="payment-amount">{ag.payment.amount} {ag.payment.currency}</span></div>
                <div className="nt-kv"><span>{t('pay.payerLabel')}</span><span className="nt-mono">{ag.payment.payer === 'A' ? t('ag.partyA') : t('ag.partyB')}</span></div>
                <div className="nt-kv"><span>{t('pay.payTo')}</span><span className="nt-mono" style={{ fontSize: 10, wordBreak: 'break-all' }} data-testid="payment-address">{ag.payment.address}</span></div>
                <div style={{ display: 'flex', justifyContent: 'center', padding: '14px 0' }}>
                  <div style={{ background: '#fff', padding: 10, borderRadius: 8 }}>
                    <QRCodeSVG value={`bitcoin:${ag.payment.address}?amount=${ag.payment.amount}&label=${encodeURIComponent(ag.title)}`} size={148} data-testid="payment-qr" />
                  </div>
                </div>
                <p className="nt-note" style={{ textAlign: 'center', margin: '0 0 12px' }}>{t('pay.scan')}</p>
                <div className="nt-actions">
                  <button className="nt-btn nt-btn-ghost" onClick={() => copy(ag.payment.address, t('ag.copied'))} data-testid="payment-copy-addr-btn">
                    <Copy size={14} strokeWidth={1.5} /> {t('pay.copyAddr')}
                  </button>
                  <a className="nt-btn nt-btn-ghost" href={`bitcoin:${ag.payment.address}?amount=${ag.payment.amount}`} data-testid="payment-open-wallet-btn">
                    <ExternalLink size={14} strokeWidth={1.5} /> {t('pay.openWallet')}
                  </a>
                  <button className="nt-btn nt-btn-ghost" onClick={checkPay} disabled={payChecking} data-testid="payment-check-btn">
                    <RefreshCw size={14} strokeWidth={1.5} className={payChecking ? 'nt-spin' : ''} /> {t('pay.checkStatus')}
                  </button>
                </div>
                {payStatus && (
                  <div style={{ marginTop: 12 }} data-testid="payment-status">
                    <div className="nt-kv"><span>{t('pay.expected')}</span><span className="nt-mono">{(payStatus.expected_sats / 1e8).toFixed(8)} BTC</span></div>
                    <div className="nt-kv"><span>{t('pay.received')}</span><span className="nt-mono">{(payStatus.received_sats / 1e8).toFixed(8)} BTC</span></div>
                    <div className="nt-kv"><span /><span className={`nt-badge ${payStatus.paid ? 'nt-badge-sealed' : 'nt-badge-pending'}`} data-testid="payment-paid-badge">{payStatus.paid ? t('pay.paid') : t('pay.unpaid')}</span></div>
                  </div>
                )}
                <p className="nt-note" style={{ margin: '12px 0 0', fontSize: 11 }}>{t('pay.noncustodial')}</p>
              </div>
            )}

            {!sealed && inviteUrl && !ag.party_b && (
              <div className="nt-card" style={{ marginBottom: 20, borderColor: 'var(--seal)' }} data-testid="invite-section">
                <div className="nt-label">{t('ag.inviteLabel')}</div>
                <div className="nt-mono" style={{ fontSize: 11, marginBottom: 12 }} data-testid="invite-link">{inviteUrl}</div>
                <button className="nt-btn nt-btn-primary" onClick={() => copy(inviteUrl, t('ag.copied'))} data-testid="invite-copy-btn">
                  <Copy size={14} strokeWidth={1.5} /> {t('ag.copyLink')}
                </button>
                <p className="nt-note" style={{ margin: '10px 0 0' }}>{t('ag.inviteNote')}</p>
              </div>
            )}

            {!sealed && (
              <div className="nt-card" style={{ marginBottom: 20 }}>
                {!iSigned ? (
                  <>
                    <button className="nt-btn nt-btn-seal" onClick={sign} disabled={signing || !ag.my_role} data-testid="sign-btn" style={{ width: '100%', justifyContent: 'center', padding: '14px' }}>
                      {signing ? t('ag.signing') : t('ag.signBtn')}
                    </button>
                    <p className="nt-note" style={{ margin: '10px 0 0', textAlign: 'center' }}>{t('ag.signNote')}</p>
                  </>
                ) : (
                  <p className="nt-note" style={{ margin: 0, textAlign: 'center' }} data-testid="already-signed-note">
                    {t('ag.alreadySigned')}
                  </p>
                )}
              </div>
            )}

            {sealed && (
              <div className="nt-card" data-testid="sealed-section">
                <div className="nt-label">{t('ag.sealedProof')}</div>
                <div className="nt-kv"><span>{t('ag.sealedAt')}</span><span className="nt-mono">{ag.sealed_at}</span></div>
                <div className="nt-kv"><span>{t('ag.proofHash')}</span><span className="nt-mono" style={{ fontSize: 10 }} data-testid="proof-hash">{ag.proof?.proof_hash}</span></div>
                <div className="nt-kv"><span>{t('ag.chatHash')}</span><span className="nt-mono" style={{ fontSize: 10 }}>{ag.proof?.chat_hash}</span></div>
                {ag.pq && <div className="nt-kv"><span>{t('ag.pqSig')}</span><span className="nt-mono">ML-DSA-87</span></div>}
                {ag.ots?.status === 'anchored_btc' && (
                  <div className="nt-kv"><span>{t('landing.certAnchorLabel')}</span>
                    <a className="nt-mono" style={{ color: 'var(--seal)', textDecoration: 'underline' }}
                      href={`https://mempool.space/block/${ag.ots.btc_block}`} target="_blank" rel="noreferrer"
                      data-testid="agreement-block-link">
                      {t('protect.viewBlock')} →
                    </a>
                  </div>
                )}
                <div className="nt-actions" style={{ marginTop: 16 }}>
                  <button className="nt-btn nt-btn-ghost" onClick={refreshOts} disabled={refreshing} data-testid="ots-refresh-btn">
                    <RefreshCw size={14} strokeWidth={1.5} className={refreshing ? 'nt-spin' : ''} /> {t('ag.checkAnchor')}
                  </button>
                  <a className="nt-btn nt-btn-ghost" href={api.certUrl(id)} target="_blank" rel="noreferrer" data-testid="cert-pdf-btn">
                    <Download size={14} strokeWidth={1.5} /> {t('ag.certPdf')}
                  </a>
                  <a className="nt-btn nt-btn-ghost" href={api.otsUrl(id)} data-testid="ots-download-btn">
                    <Download size={14} strokeWidth={1.5} /> {t('ag.otsProof')}
                  </a>
                  <Link className="nt-btn nt-btn-ghost" to={`/certificado/${id}`} data-testid="cert-page-link">
                    <ExternalLink size={14} strokeWidth={1.5} /> {t('ag.publicCert')}
                  </Link>
                </div>
              </div>
            )}
          </div>

          <aside className="nt-chat" data-testid="chat-panel">
            <div className="nt-chat-head">
              <Lock size={11} strokeWidth={1.5} style={{ verticalAlign: '-1px', marginRight: 5 }} />
              {t('ag.chatHead')}{frozen ? t('ag.chatFrozenSuffix') : ''}
              {!frozen && sharedKey && <span data-testid="chat-e2e-badge" style={{ marginLeft: 6, color: 'var(--seal)', fontSize: 10, fontWeight: 700 }} title={pqActive ? 'X-Wing: ML-KEM-768 + X25519 (post-quantum hybrid)' : 'ECDH P-256'}>{pqActive ? '● E2E·PQ' : '● E2E'}</span>}
            </div>
            <div className="nt-chat-body">
              {view.length === 0 && <div className="nt-note" style={{ textAlign: 'center', margin: 'auto' }}>{t('ag.chatEmpty')}</div>}
              {view.map((m, i) => (
                <div key={i} className={`nt-msg ${m.sender === user?.email ? 'nt-msg-me' : 'nt-msg-them'}`} data-testid="chat-message">
                  {m.locked ? (
                    <span style={{ opacity: 0.6, fontStyle: 'italic' }} data-testid="chat-message-locked">
                      <Lock size={11} strokeWidth={1.5} style={{ verticalAlign: '-1px', marginRight: 4 }} />{t('ag.msgLocked')}
                    </span>
                  ) : m.text}
                  <span className="t">{m.sender === user?.email ? t('ag.you') : m.sender} · {new Date(m.ts).toLocaleString(locale, { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' })}</span>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>
            {frozen ? (
              <div className="nt-chat-input" style={{ justifyContent: 'center' }}>
                <span className="nt-note nt-mono" data-testid="chat-frozen-note">{t('ag.chatFrozenNote')}</span>
              </div>
            ) : !sharedKey ? (
              <div className="nt-chat-input" style={{ justifyContent: 'center' }}>
                <span className="nt-note nt-mono" data-testid="chat-e2e-waiting">{t('ag.e2eWaiting')}</span>
              </div>
            ) : (
              <div className="nt-chat-input">
                <input className="nt-input" value={text}
                  onChange={(e) => setText(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && send()}
                  placeholder={t('ag.chatPh')} maxLength={4000}
                  data-testid="chat-input" />
                <button className="nt-btn nt-btn-primary" onClick={send} disabled={!text.trim()} data-testid="chat-send-btn">
                  <Send size={14} strokeWidth={1.5} />
                </button>
              </div>
            )}
          </aside>
        </div>
      </main>
    </div>
  );
}
