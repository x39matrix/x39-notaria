import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { FileText, PenLine, Anchor, ShieldCheck, Users, Coins, Atom, SearchCheck } from 'lucide-react';
import { Nav } from './Nav';
import { useAuth } from './NotariaApp';
import { useLang } from './i18n';
import { api, loginWithGoogle } from './api';

const DEMO_CERT_ID = 'demo0000demo0001';
const STEP_ICONS = [FileText, PenLine, Anchor];

export default function Landing() {
  const { user } = useAuth();
  const { t } = useLang();
  const navigate = useNavigate();
  const [demoProof, setDemoProof] = useState(null);

  useEffect(() => {
    api.publicProof(DEMO_CERT_ID).then(setDemoProof).catch(() => setDemoProof(null));
  }, []);

  const createFirst = () => {
    if (user) navigate('/crear');
    else loginWithGoogle('/crear');
  };

  const steps = [1, 2, 3].map((n, i) => ({
    icon: STEP_ICONS[i],
    t: t(`landing.s${n}t`),
    d: t(`landing.s${n}d`),
  }));

  return (
    <div data-testid="landing-page">
      <Nav />
      <a href="https://app.emergent.sh/showcase/fabrizio/121cef04-5dc5-49b8-a930-9877306f620b"
        target="_blank" rel="noopener noreferrer" data-testid="contest-vote-banner"
        style={{ display: 'block', textAlign: 'center', padding: '9px 14px', fontSize: 12,
                 background: 'var(--seal)', color: '#fff', textDecoration: 'none', letterSpacing: '0.02em' }}>
        {t('landing.voteContest')} →
      </a>
      <main className="nt-wrap">
        <section className="nt-hero">
          <div>
            <div className="nt-label" style={{ marginBottom: 14 }}>{t('landing.tag')}</div>
            <h1>{t('landing.h1')}</h1>
            <p className="nt-serif" style={{ fontSize: 20, fontStyle: 'italic', color: 'var(--fg)', margin: '0 0 14px', maxWidth: '44ch', lineHeight: 1.35 }}>
              {t('landing.h1b')}
            </p>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '0 0 14px' }} data-testid="hero-pq-chips">
              <span className="nt-mono" style={{ fontSize: 11, border: '1px solid var(--seal)', color: 'var(--seal)', borderRadius: 999, padding: '4px 10px' }}>
                {t('landing.chipPq')}
              </span>
              <span className="nt-mono" style={{ fontSize: 11, border: '1px solid var(--border)', color: 'var(--muted)', borderRadius: 999, padding: '4px 10px' }}>
                {t('landing.chipBtc')}
              </span>
              <span className="nt-mono" style={{ fontSize: 11, border: '1px solid var(--border)', color: 'var(--muted)', borderRadius: 999, padding: '4px 10px' }}>
                {t('landing.chipTrust')}
              </span>
            </div>
            <p>{t('landing.sub')}</p>
            <div className="nt-hero-actions">
              <button className="nt-btn nt-btn-seal" onClick={createFirst} data-testid="landing-cta-start">
                {t('landing.ctaPrimary')}
              </button>
              <Link to={`/certificado/${DEMO_CERT_ID}#verificador`} className="nt-btn nt-btn-ghost" data-testid="landing-cta-verify-self">
                {t('landing.ctaVerifySelf')}
              </Link>
            </div>
          </div>
          <div role="link" tabIndex={0} onClick={() => navigate(`/certificado/${DEMO_CERT_ID}`)}
            onKeyDown={(e) => { if (e.key === 'Enter') navigate(`/certificado/${DEMO_CERT_ID}`); }}
            className="nt-hero-visual" style={{ display: 'block', color: 'inherit', cursor: 'pointer' }} data-testid="hero-demo-cert">
            <div style={{ textAlign: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 16, marginBottom: 18 }}>
              <div className="nt-label" style={{ marginBottom: 4 }}>X-39 Notaría</div>
              <div className="nt-serif" style={{ fontSize: 26, fontWeight: 600 }}>{t('landing.certTitle')}</div>
            </div>
            <div className="nt-label">{t('landing.certHashLabel')}</div>
            <div className="nt-mono" style={{ fontSize: 11, marginBottom: 14 }} data-testid="hero-cert-hash">
              {demoProof ? demoProof.content_hash : '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'}
            </div>
            <div className="nt-label">{t('landing.certAnchorLabel')}</div>
            {demoProof ? (
              demoProof.ots_status === 'anchored_btc' ? (
                <>
                  <span className="nt-badge nt-badge-sealed" style={{ marginBottom: 8 }} data-testid="hero-cert-anchor">{t('ag.badgeConfirmedIn')}{demoProof.btc_block}</span>
                  <div>
                    <a className="nt-mono" style={{ fontSize: 11, color: 'var(--seal)', textDecoration: 'underline' }}
                      href={`https://mempool.space/block/${demoProof.btc_block}`} target="_blank" rel="noreferrer"
                      onClick={(e) => e.stopPropagation()} data-testid="hero-block-link">
                      {t('protect.viewBlock')} →
                    </a>
                  </div>
                </>
              ) : (
                <span className="nt-badge nt-badge-draft" style={{ marginBottom: 8 }} data-testid="hero-cert-anchor">{t('landing.certRealBadgePending')}</span>
              )
            ) : (
              <span className="nt-badge nt-badge-sealed" style={{ marginBottom: 8 }}>{t('landing.certMockBadge')}</span>
            )}
            {demoProof?.pq && (
              <>
                <div className="nt-label" style={{ marginTop: 12 }}>{t('ag.pqSig')}</div>
                <div className="nt-mono" style={{ fontSize: 11 }} data-testid="hero-cert-pq">ML-DSA-87 (FIPS-204)</div>
              </>
            )}
            <div className="nt-seal-stamp" style={{ width: 92, height: 92, marginTop: 16 }}>
              <span className="big">{t('landing.sealedStamp')}</span>
              <span className="sm">X-39 Notaría</span>
            </div>
            {demoProof && (
              <div className="nt-note" style={{ textAlign: 'center', marginTop: 14, textDecoration: 'underline' }} data-testid="hero-cert-open">
                {t('landing.certOpen')} →
              </div>
            )}
          </div>
        </section>

        <section className="nt-steps">
          {steps.map((s, i) => (
            <div className="nt-step" key={s.t}>
              <div className="n">{String(i + 1).padStart(2, '0')}</div>
              <h3><s.icon size={15} strokeWidth={1.5} style={{ verticalAlign: '-2px', marginRight: 6 }} />{s.t}</h3>
              <p>{s.d}</p>
            </div>
          ))}
        </section>

        <section style={{ marginBottom: 20 }} data-testid="landing-protect">
          <h2 className="nt-serif" style={{ fontSize: 26, fontWeight: 600, margin: '0 0 16px' }}>{t('protect.title')}</h2>
          <div className="nt-steps" style={{ margin: 0 }}>
            {[{ icon: Anchor, k: 'b1' }, { icon: Atom, k: 'b2' }, { icon: SearchCheck, k: 'b3' }].map(({ icon: Icon, k }) => (
              <div className="nt-step" key={k}>
                <Icon size={20} strokeWidth={1.5} color="var(--seal)" />
                <h3>{t(`protect.${k}t`)}</h3>
                <p>{t(`protect.${k}d`)}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="nt-card nt-card-pad" style={{ marginBottom: 20 }} data-testid="landing-forwho">
          <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
            <Users size={22} strokeWidth={1.5} color="var(--seal)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <h2 className="nt-serif" style={{ fontSize: 22, margin: '0 0 8px', fontWeight: 600 }}>{t('landing.forWhoTitle')}</h2>
              <p className="nt-note" style={{ fontSize: 14, maxWidth: '70ch', margin: 0 }}>{t('landing.forWho')}</p>
            </div>
          </div>
        </section>

        <section className="nt-card nt-card-pad" style={{ marginBottom: 20 }} data-testid="landing-pricing">
          <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
            <Coins size={22} strokeWidth={1.5} color="var(--seal)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <h2 className="nt-serif" style={{ fontSize: 22, margin: '0 0 8px', fontWeight: 600 }}>
                {t('landing.priceTitle')} <span className="nt-pill-demo" style={{ verticalAlign: '3px', marginLeft: 6 }}>x39 · {t('landing.soon')}</span>
              </h2>
              <p className="nt-note" style={{ fontSize: 14, maxWidth: '70ch', margin: 0 }}>{t('landing.priceX39')}</p>
            </div>
          </div>
        </section>

        <section className="nt-card nt-card-pad" style={{ marginBottom: 64 }}>
          <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
            <ShieldCheck size={22} strokeWidth={1.5} color="var(--seal)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <h2 className="nt-serif" style={{ fontSize: 22, margin: '0 0 8px', fontWeight: 600 }}>{t('landing.honestyTitle')}</h2>
              <p className="nt-note" style={{ fontSize: 14, maxWidth: '70ch', margin: 0 }}>{t('landing.honestyBody')}</p>
            </div>
          </div>
        </section>
      </main>
      <footer style={{ borderTop: '1px solid var(--border)', padding: '24px 0' }}>
        <div className="nt-wrap" style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
          <span className="nt-note">{t('landing.footer')}</span>
          <span className="nt-note nt-mono">
            OpenTimestamps · SHA-256 · ML-DSA-87
          </span>
        </div>
      </footer>
    </div>
  );
}
