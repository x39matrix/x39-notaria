import React, { createContext, useContext, useEffect, useState } from 'react';
import { Routes, Route, useLocation, Navigate } from 'react-router-dom';
import { Toaster } from 'sonner';
import { api } from './api';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/700.css';
import '@fontsource/chivo/400.css';
import '@fontsource/chivo/700.css';
import '@fontsource/chivo/900.css';
import '@fontsource/cormorant-garamond/400.css';
import '@fontsource/cormorant-garamond/400-italic.css';
import '@fontsource/cormorant-garamond/500.css';
import '@fontsource/cormorant-garamond/600.css';
import '@fontsource/cormorant-garamond/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import '@fontsource/manrope/400.css';
import '@fontsource/manrope/500.css';
import '@fontsource/manrope/600.css';
import '@fontsource/manrope/700.css';
import './notaria.css';
import { LangProvider, useLang, LANGS } from './i18n';
import Landing from './Landing';
import Panel from './Panel';
import Crear from './Crear';
import Acuerdo from './Acuerdo';
import Unirse from './Unirse';
import Verificar from './Verificar';
import Certificado from './Certificado';
import Entrar from './Entrar';
import Privacidad from './Privacidad';
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
function SeoLinks() {
  const { lang } = useLang();
  const location = useLocation();
  useEffect(() => {
    const base = 'https://x39matrix.org' + location.pathname;
    const set = (rel, hreflang, href) => {
      const sel = hreflang ? `link[rel="${rel}"][hreflang="${hreflang}"]` : `link[rel="${rel}"]`;
      let el = document.head.querySelector(sel);
      if (!el) { el = document.createElement('link'); el.rel = rel; if (hreflang) el.hreflang = hreflang; document.head.appendChild(el); }
      el.href = href;
    };
    set('canonical', null, lang === 'en' ? base : `${base}?lang=${lang}`);
    LANGS.forEach((l) => set('alternate', l.code, l.code === 'en' ? base : `${base}?lang=${l.code}`));
    set('alternate', 'x-default', base);
  }, [lang, location.pathname]);
  return null;
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
        <SeoLinks />
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/entrar" element={<Entrar />} />
          <Route path="/panel" element={<Protected><Panel /></Protected>} />
          <Route path="/crear" element={<Protected><Crear /></Protected>} />
          <Route path="/acuerdo/:id" element={<Protected><Acuerdo /></Protected>} />
          <Route path="/unirse/:id" element={<Unirse />} />
          <Route path="/verificar" element={<Verificar />} />
          <Route path="/certificado/:id" element={<Certificado />} />
          <Route path="/privacidad" element={<Privacidad />} />
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
