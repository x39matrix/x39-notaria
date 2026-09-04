import React, { createContext, useContext, useEffect, useState } from 'react';
import { Routes, Route, useLocation, Navigate } from 'react-router-dom';
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
import Entrar from './Entrar';
const AuthCtx = createContext(null);
export const useAuth = () => useContext(AuthCtx);
function Protected({ children }) {
  const { user, loading } = useAuth();
  const { t } = useLang();
  const location = useLocation();
  if (loading) {
    return <div className="nt-center"><div className="nt-note nt-mono">{t('common.loading')}</div></div>;
  }
  if (!user) {
    const next = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/entrar?next=${next}`} replace />;
  }
  return children;
}
function NotariaInner() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.me()
      .then((u) => setUser(u))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);
  return (
    <AuthCtx.Provider value={{ user, setUser, loading }}>
      <div className="nt">
        <Toaster position="top-center" toastOptions={{ style: { fontFamily: 'Manrope, sans-serif' } }} />
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/entrar" element={<Entrar />} />
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
