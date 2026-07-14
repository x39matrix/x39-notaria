import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import { Download, Share2 } from 'lucide-react';
import { Nav } from './Nav';
import { useLang } from './i18n';
import { api } from './api';
import { VerificadorIndependiente } from './VerificadorIndependiente';

export default function Certificado() {
  const { id } = useParams();
  const { t } = useLang();
  const [proof, setProof] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.publicProof(id).then(setProof).catch((e) => setError(e.message));
  }, [id]);

  const share = async () => {
    const url = api.shareUrl(id);
    if (navigator.share) {
      try { await navigator.share({ title: 'X-39 Notaría', url }); return; } catch { /* cancelled */ }
    }
    navigator.clipboard.writeText(url).then(() => toast.success(t('cert.shareCopied')));
  };

  if (error) {
    return (
      <div><Nav />
        <main className="nt-wrap nt-center"><div className="nt-card nt-card-pad" style={{ textAlign: 'center' }}>
          <p className="nt-serif" style={{ fontSize: 22 }} data-testid="cert-error">{error}</p>
          <Link to="/verificar" className="nt-btn nt-btn-ghost">{t('cert.goVerify')}</Link>
        </div></main>
      </div>
    );
  }
  if (!proof) return <div><Nav /><div className="nt-center"><div className="nt-note nt-mono">{t('common.loading')}</div></div></div>;

  const anchored = proof.ots_status === 'anchored_btc';

  return (
    <div data-testid="certificado-page">
      <Nav />
      <main className="nt-wrap" style={{ padding: '40px 20px 80px' }}>
        <div className="nt-cert">
          <div className="nt-cert-head">
            <div className="k">X-39 Notaría</div>
            <h2>{t('landing.certTitle')}</h2>
            <div className="nt-note" style={{ fontStyle: 'italic' }}>{t('cert.sub')}</div>
          </div>

          <div className="nt-cert-row"><div className="nt-label">{t('ver.fTitle')}</div><div data-testid="cert-title">{proof.title}</div></div>
          <div className="nt-cert-row"><div className="nt-label">{t('landing.certHashLabel')}</div><div className="nt-mono" style={{ fontSize: 11 }} data-testid="cert-content-hash">{proof.content_hash}</div></div>
          <div className="nt-cert-row"><div className="nt-label">{t('ag.proofHash')}</div><div className="nt-mono" style={{ fontSize: 11 }}>{proof.proof_hash}</div></div>
          <div className="nt-cert-row"><div className="nt-label">{t('ag.parties')}</div><div className="nt-mono" style={{ fontSize: 11 }} data-testid="cert-parties-fp">{proof.party_a_fp ? `${proof.party_a_fp.slice(0, 24)}…` : '—'} · {proof.party_b_fp ? `${proof.party_b_fp.slice(0, 24)}…` : '—'}</div></div>
          <div className="nt-cert-row"><div className="nt-label">{t('ag.sealedAt')}</div><div className="nt-mono" style={{ fontSize: 12 }}>{proof.sealed_at}</div></div>
          {proof.payment && (
            <div className="nt-cert-row" data-testid="cert-payment">
              <div className="nt-label">{t('pay.terms')}</div>
              <div className="nt-mono" style={{ fontSize: 11 }}>
                {proof.payment.amount} {proof.payment.currency} · {t('pay.payerLabel')}: {proof.payment.payer}
                <div style={{ wordBreak: 'break-all', marginTop: 4 }}>{proof.payment.address}</div>
              </div>
            </div>
          )}
          <div className="nt-cert-row">
            <div className="nt-label">{t('landing.certAnchorLabel')}</div>
            {anchored
              ? <span className="nt-badge nt-badge-sealed" data-testid="cert-ots-status">{t('ag.badgeConfirmedIn')}{proof.btc_block}</span>
              : <span className="nt-badge nt-badge-pending" data-testid="cert-ots-status">{t('cert.pendingOts')}</span>}
            {anchored && (
              <div style={{ marginTop: 8 }}>
                <a className="nt-mono" style={{ fontSize: 11, color: 'var(--seal)', textDecoration: 'underline' }}
                  href={`https://mempool.space/block/${proof.btc_block}`} target="_blank" rel="noreferrer"
                  data-testid="cert-block-link">
                  {t('protect.viewBlock')} →
                </a>
              </div>
            )}
          </div>
          {proof.pq && (
            <div className="nt-cert-row"><div className="nt-label">{t('ag.pqSig')}</div><div className="nt-mono" style={{ fontSize: 12 }}>ML-DSA-87 (FIPS-204)</div></div>
          )}

          <div className={`nt-seal-stamp ${anchored ? 'stamped' : ''}`}>
            <span className="big">{t('landing.sealedStamp')}</span>
            <span className="sm">X-39 Notaría</span>
          </div>
        </div>

        <div className="nt-actions" style={{ justifyContent: 'center', marginTop: 26 }}>
          <a className="nt-btn nt-btn-primary" href={api.certUrl(id)} target="_blank" rel="noreferrer" data-testid="cert-download-pdf">
            <Download size={14} strokeWidth={1.5} /> {t('cert.downloadPdf')}
          </a>
          <a className="nt-btn nt-btn-ghost" href={api.bundleUrl(id)} data-testid="cert-download-bundle">
            <Download size={14} strokeWidth={1.5} /> {t('cert.bundle')}
          </a>
          <a className="nt-btn nt-btn-ghost" href={api.otsUrl(id)} data-testid="cert-download-ots">
            <Download size={14} strokeWidth={1.5} /> {t('ag.otsProof')}
          </a>
          <a className="nt-btn nt-btn-ghost" href={api.proofJsonUrl(id)} data-testid="cert-download-json">
            <Download size={14} strokeWidth={1.5} /> {t('cert.payloadJson')}
          </a>
          <button className="nt-btn nt-btn-ghost" onClick={share} data-testid="cert-share-btn">
            <Share2 size={14} strokeWidth={1.5} /> {t('cert.share')}
          </button>
        </div>
        <p className="nt-note" style={{ textAlign: 'center', marginTop: 16 }}>{t('cert.indepNote')}</p>
        <p className="nt-note" style={{ textAlign: 'center', marginTop: 10, maxWidth: '80ch', marginLeft: 'auto', marginRight: 'auto' }} data-testid="cert-legal-scope">
          {t('cert.legalScope')}
        </p>

        <VerificadorIndependiente proof={proof} id={id} />
      </main>
    </div>
  );
}
