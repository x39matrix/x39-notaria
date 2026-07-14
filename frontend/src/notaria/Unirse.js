import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { Nav } from './Nav';
import { useAuth } from './NotariaApp';
import { useLang } from './i18n';
import { api, loginWithGoogle } from './api';

export default function Unirse() {
  const { id } = useParams();
  const [params] = useSearchParams();
  const token = params.get('t') || '';
  const { user, loading } = useAuth();
  const { t } = useLang();
  const navigate = useNavigate();
  const [error, setError] = useState(null);
  const joined = useRef(false);

  useEffect(() => {
    if (loading || !user || joined.current) return;
    joined.current = true;
    api.join(id, token)
      .then(() => navigate(`/acuerdo/${id}`, { replace: true }))
      .catch((e) => setError(e.message));
  }, [loading, user, id, token, navigate]);

  return (
    <div data-testid="unirse-page">
      <Nav />
      <main className="nt-wrap nt-center">
        <div className="nt-card nt-card-pad" style={{ maxWidth: 480, textAlign: 'center' }}>
          {loading && <p className="nt-note nt-mono">{t('common.loading')}</p>}
          {!loading && !user && (
            <>
              <div className="nt-label">{t('join.kicker')}</div>
              <h1 className="nt-serif" style={{ fontSize: 28, fontWeight: 600, margin: '0 0 10px' }}>{t('join.title')}</h1>
              <p className="nt-note" style={{ margin: '0 0 22px' }}>{t('join.body')}</p>
              <button className="nt-btn nt-btn-seal" style={{ width: '100%', justifyContent: 'center', padding: 14 }}
                onClick={() => loginWithGoogle(`/unirse/${id}?t=${token}`)}
                data-testid="join-login-btn">
                {t('join.cta')}
              </button>
            </>
          )}
          {!loading && user && !error && <p className="nt-note nt-mono" data-testid="join-progress">{t('join.progress')}</p>}
          {error && (
            <>
              <p className="nt-serif" style={{ fontSize: 22, color: 'var(--error)', margin: '0 0 12px' }} data-testid="join-error">{error}</p>
              <button className="nt-btn nt-btn-ghost" onClick={() => navigate('/panel')}>{t('common.goToPanel')}</button>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
