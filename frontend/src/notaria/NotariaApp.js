import React, { createContext, useContext, useEffect, useRef, useState } from 'react';
import { Routes, Route, useLocation, useNavigate, Navigate } from 'react-router-dom';
import { Toaster } from 'sonner';
import { api } from './api';
import './notaria.css';
import { LangProvider, useLang } from './i18n';
import Landing from './Landing';
import Panel from './Panel';
import Crear from './Crear';
import Acuerdo from './Acuerdo';
import Unirse from './Unirse';
import Verificar from './Verificar';
import Certificado from './Certificado';

const AuthCtx = createContext(null);
export const useAuth = () => useContext(AuthCtx);

function AuthCallback({ onUser }) {
  const navigate = useNavigate();
  const { t } = useLang();
  const hasProcessed = useRef(false);
  useEffect(() => {
    if (hasProcessed.current) return;
    hasProcessed.current = true;
    const sid = new URLSearchParams(window.location.hash.slice(1)).get('session_id');
    (async () => {
      try {
        const user = await api.exchangeSession(sid);
        onUser(user);
        const dest = window.location.pathname + window.location.search;
        navigate(dest === '/' ? '/panel' : dest, { replace: true, state: { user } });
      } catch {
        navigate('/', { replace: true });
      }
    })();
  }, [navigate, onUser]);
  return (
    <div className="nt nt-center">
      <div className="nt-note nt-mono" data-testid="auth-callback-loading">{t('common.verifyingIdentity')}</div>
    </div>
  );
}

function Protected({ children }) {
  const { user, loading } = useAuth();
  const { t } = useLang();
  if (loading) {
    return <div className="nt-center"><div className="nt-note nt-mono">{t('common.loading')}</div></div>;
  }
  if (!user) return <Navigate to="/" replace />;
  return children;
}

function NotariaInner() {
  const location = useLocation();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // CRITICAL: si volvemos del OAuth callback, AuthCallback intercambia el session_id primero.
    if (window.location.hash?.includes('session_id=')) {
      setLoading(false);
      return;
    }
    api.me()
      .then((u) => setUser(u))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  if (location.hash?.includes('session_id=')) {
    return <AuthCallback onUser={(u) => { setUser(u); setLoading(false); }} />;
  }

  return (
    <AuthCtx.Provider value={{ user, setUser, loading }}>
      <div className="nt">
        <Toaster position="top-center" toastOptions={{ style: { fontFamily: 'Manrope, sans-serif' } }} />
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/panel" element={<Protected><Panel /></Protected>} />
          <Route path="/crear" element={<Protected><Crear /></Protected>} />
          <Route path="/acuerdo/:id" element={<Protected><Acuerdo /></Protected>} />
          <Route path="/unirse/:id" element={<Unirse />} />
          <Route path="/verificar" element={<Verificar />} />
          <Route path="/certificado/:id" element={<Certificado />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </AuthCtx.Provider>
  );
}

export default function NotariaApp() {
  return (
    <LangProvider>
      <NotariaInner />
    </LangProvider>
  );
}
