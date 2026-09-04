import React from 'react';
import { Nav } from './Nav';
import { useLang } from './i18n';

export default function Privacidad() {
  const { t } = useLang();
  return (
    <div data-testid="privacidad-page">
      <Nav />
      <main className="nt-wrap" style={{ padding: '40px 20px 80px' }}>
        <div className="nt-card nt-card-pad" style={{ maxWidth: 760, margin: '0 auto' }}>
          <h1 className="nt-serif" style={{ fontSize: 28, fontWeight: 600, margin: '0 0 16px' }}>{t('privacy.title')}</h1>
          {['p1', 'p2', 'p3', 'p4'].map((k) => (
            <p key={k} className="nt-note" style={{ fontSize: 14, lineHeight: 1.6, margin: '0 0 12px' }}>{t(`privacy.${k}`)}</p>
          ))}
        </div>
      </main>
    </div>
  );
}
