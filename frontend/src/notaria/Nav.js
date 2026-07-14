import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { LogOut } from 'lucide-react';
import { useAuth } from './NotariaApp';
import { useLang, LANGS } from './i18n';
import { api, loginWithGoogle } from './api';

export const Nav = () => {
  const { user, setUser } = useAuth();
  const { lang, setLang, t } = useLang();
  const navigate = useNavigate();

  const logout = async () => {
    try { await api.logout(); } catch { /* noop */ }
    setUser(null);
    navigate('/');
  };

  return (
    <nav className="nt-nav">
      <div className="nt-wrap nt-nav-inner">
        <Link to={user ? '/panel' : '/'} className="nt-brand" data-testid="nav-brand">
          <span className="seal-dot" />
          X-39 Notaría
        </Link>
        <div className="nt-nav-links">
          <Link to="/verificar" className="nt-btn nt-btn-ghost" data-testid="nav-verify-link">{t('nav.verify')}</Link>
          {user ? (
            <>
              <Link to="/panel" className="nt-btn nt-btn-ghost" data-testid="nav-panel-link">{t('nav.panel')}</Link>
              <button className="nt-btn nt-btn-ghost" onClick={logout} data-testid="nav-logout-btn" title={user.email}>
                <LogOut size={15} strokeWidth={1.5} />
              </button>
            </>
          ) : (
            <button className="nt-btn nt-btn-primary" onClick={() => loginWithGoogle('/panel')} data-testid="nav-login-btn">
              {t('nav.login')}
            </button>
          )}
          <span className="nt-langbar" data-testid="lang-toggle-btn" role="group" aria-label="Language">
            {LANGS.map((l) => (
              <button key={l.code} className={`nt-langflag ${lang === l.code ? 'on' : ''}`}
                onClick={() => setLang(l.code)} data-testid={`lang-btn-${l.code}`} title={l.label}>
                <span aria-hidden="true">{l.flag}</span> <span className="nt-langlabel">{l.label}</span>
              </button>
            ))}
          </span>
        </div>
      </div>
    </nav>
  );
};
