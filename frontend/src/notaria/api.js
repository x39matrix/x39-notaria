const API = process.env.REACT_APP_BACKEND_URL;
const BASE = `${API}/api/notaria`;

let _csrf = null;

async function req(path, { method = 'GET', body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (method !== 'GET' && _csrf) headers['X-CSRF-Token'] = _csrf;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    credentials: 'include',
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.detail || `Error ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

export const api = {
  exchangeSession: async (session_id) => {
    const d = await req('/auth/session', { method: 'POST', body: { session_id } });
    if (d.csrf_token) _csrf = d.csrf_token;
    return d;
  },
  me: async () => {
    const d = await req('/auth/me');
    if (d.authenticated === false) return null;
    if (d.csrf_token) _csrf = d.csrf_token;
    return d;
  },
  logout: async () => {
    const d = await req('/auth/logout', { method: 'POST' });
    _csrf = null;
    Object.keys(localStorage).filter((k) => k.startsWith('nt_e2e_')).forEach((k) => localStorage.removeItem(k));
    return d;
  },
  listAgreements: () => req('/agreements'),
  createAgreement: (payload) => req('/agreements', { method: 'POST', body: payload }),
  getAgreement: (id) => req(`/agreements/${id}`),
  join: (id, invite_token) => req(`/agreements/${id}/join`, { method: 'POST', body: { invite_token } }),
  sign: (id) => req(`/agreements/${id}/sign`, { method: 'POST' }),
  getMessages: (id) => req(`/agreements/${id}/messages`),
  postMessage: (id, ct, iv) => req(`/agreements/${id}/messages`, { method: 'POST', body: { ct, iv } }),
  publishE2EKey: (id, public_key_jwk) => req(`/agreements/${id}/e2e_key`, { method: 'POST', body: { public_key_jwk } }),
  getE2EKeys: (id) => req(`/agreements/${id}/e2e_keys`),
  refreshOts: (id) => req(`/agreements/${id}/ots/refresh`, { method: 'POST' }),
  verify: (hash) => req('/verify', { method: 'POST', body: { hash } }),
  publicProof: (id) => req(`/public/${id}`),
  paymentStatus: (id) => req(`/agreements/${id}/payment_status`),
  certUrl: (id) => `${BASE}/certificate/${id}.pdf`,
  bundleUrl: (id) => `${BASE}/proof/${id}.zip`,
  otsUrl: (id) => `${BASE}/proof/${id}.ots`,
  proofJsonUrl: (id) => `${BASE}/proof/${id}.json`,
  shareUrl: (id) => `${BASE}/p/${id}`,
};

// REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
export function loginWithGoogle(returnPath = '/panel') {
  const redirectUrl = window.location.origin + returnPath;
  window.location.href = `https://auth.emergentagent.com/?redirect=${encodeURIComponent(redirectUrl)}`;
}

// SHA-256 en el navegador (el archivo NUNCA se sube)
export async function sha256Hex(bufferOrString) {
  const data = typeof bufferOrString === 'string'
    ? new TextEncoder().encode(bufferOrString)
    : bufferOrString;
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256File(file) {
  const buf = await file.arrayBuffer();
  return sha256Hex(buf);
}
