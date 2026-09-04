// Entrar.js — Entrada por llave (Ed25519). Tu llave ES tu identidad: sin correo, sin terceros.
// Al crear identidad se OBLIGA a guardar la copia de seguridad antes de entrar.
import React, { useState } from 'react';
import { useNavigate, useSearchParams, Navigate } from 'react-router-dom';
import { useAuth } from './NotariaApp';
import { useLang } from './i18n';
import { api } from './api';
import { hasKey, createKey, exportBlock, importBlock, login } from './id';

const STR = {
  es: {
    title: 'Tu llave es tu identidad',
    intro: 'Sin correo, sin contraseñas en servidores: una llave criptográfica que solo tú tienes, guardada en tu dispositivo.',
    btnCreate: 'Crear identidad nueva',
    btnHaveKey: 'Ya tengo una llave',
    backupTitle: 'Guarda tu copia de seguridad ahora',
    backupWarn: 'Esta es tu llave privada. Si pierdes este dispositivo o borras los datos del navegador y no tienes copia, tu identidad se pierde para siempre. Nadie puede recuperarla por ti.',
    btnDownload: 'Descargar copia (.txt)',
    btnCopy: 'Copiar',
    copied: 'Copiada',
    savedCheck: 'He guardado mi copia en un lugar seguro',
    btnEnter: 'Entrar',
    haveKeyTitle: 'Este dispositivo ya tiene una llave',
    haveKeyNote: 'Puedes entrar directamente. Si aún no tienes copia de seguridad de esta llave, descárgala.',
    btnUseOther: 'Usar otra llave',
    importTitle: 'Pega tu llave',
    importHint: 'Formato: X39KEY-v1:…',
    importWarnReplace: 'Atención: esto sustituye la llave actual de este dispositivo.',
    btnImportEnter: 'Importar y entrar',
    back: 'Volver',
  },
  en: {
    title: 'Your key is your identity',
    intro: 'No email, no server passwords: a cryptographic key only you hold, stored on your device.',
    btnCreate: 'Create new identity',
    btnHaveKey: 'I already have a key',
    backupTitle: 'Save your backup now',
    backupWarn: 'This is your private key. If you lose this device or clear browser data without a backup, your identity is lost forever. Nobody can recover it for you.',
    btnDownload: 'Download backup (.txt)',
    btnCopy: 'Copy',
    copied: 'Copied',
    savedCheck: 'I have saved my backup somewhere safe',
    btnEnter: 'Sign in',
    haveKeyTitle: 'This device already has a key',
    haveKeyNote: 'You can sign in directly. If you have no backup of this key yet, download it.',
    btnUseOther: 'Use another key',
    importTitle: 'Paste your key',
    importHint: 'Format: X39KEY-v1:…',
    importWarnReplace: 'Warning: this replaces the current key on this device.',
    btnImportEnter: 'Import and sign in',
    back: 'Back',
  },
  zh: {
    title: '你的密钥就是你的身份',
    intro: '无需邮箱，无需服务器密码：一把只有你持有、保存在你设备上的加密密钥。',
    btnCreate: '创建新身份',
    btnHaveKey: '我已有密钥',
    backupTitle: '立即保存你的备份',
    backupWarn: '这是你的私钥。如果丢失此设备或清除浏览器数据且没有备份，你的身份将永远丢失，任何人都无法为你恢复。',
    btnDownload: '下载备份 (.txt)',
    btnCopy: '复制',
    copied: '已复制',
    savedCheck: '我已将备份保存在安全的地方',
    btnEnter: '进入',
    haveKeyTitle: '此设备已有密钥',
    haveKeyNote: '你可以直接进入。如果尚未备份此密钥，请先下载。',
    btnUseOther: '使用其他密钥',
    importTitle: '粘贴你的密钥',
    importHint: '格式：X39KEY-v1:…',
    importWarnReplace: '注意：这将替换此设备上的当前密钥。',
    btnImportEnter: '导入并进入',
    back: '返回',
  },
  ja: {
    title: 'あなたの鍵があなたのアイデンティティ',
    intro: 'メールもサーバーのパスワードも不要。あなただけが持ち、端末に保存される暗号鍵です。',
    btnCreate: '新しいアイデンティティを作成',
    btnHaveKey: '既に鍵を持っている',
    backupTitle: '今すぐバックアップを保存',
    backupWarn: 'これはあなたの秘密鍵です。端末を失うかブラウザのデータを消去し、バックアップがない場合、アイデンティティは永久に失われます。誰にも復元できません。',
    btnDownload: 'バックアップをダウンロード (.txt)',
    btnCopy: 'コピー',
    copied: 'コピーしました',
    savedCheck: '安全な場所にバックアップを保存しました',
    btnEnter: '入る',
    haveKeyTitle: 'この端末には既に鍵があります',
    haveKeyNote: 'そのまま入れます。この鍵のバックアップがまだ無ければダウンロードしてください。',
    btnUseOther: '別の鍵を使う',
    importTitle: '鍵を貼り付け',
    importHint: '形式：X39KEY-v1:…',
    importWarnReplace: '注意：この端末の現在の鍵を置き換えます。',
    btnImportEnter: 'インポートして入る',
    back: '戻る',
  },
  ar: {
    title: 'مفتاحك هو هويتك',
    intro: 'بلا بريد إلكتروني وبلا كلمات مرور على الخوادم: مفتاح تشفير لا يملكه أحد سواك، محفوظ في جهازك.',
    btnCreate: 'إنشاء هوية جديدة',
    btnHaveKey: 'لدي مفتاح بالفعل',
    backupTitle: 'احفظ نسختك الاحتياطية الآن',
    backupWarn: 'هذا هو مفتاحك الخاص. إذا فقدت هذا الجهاز أو مسحت بيانات المتصفح دون نسخة احتياطية، تُفقد هويتك إلى الأبد ولا يمكن لأحد استعادتها.',
    btnDownload: 'تنزيل النسخة (.txt)',
    btnCopy: 'نسخ',
    copied: 'تم النسخ',
    savedCheck: 'حفظت نسختي في مكان آمن',
    btnEnter: 'دخول',
    haveKeyTitle: 'هذا الجهاز لديه مفتاح بالفعل',
    haveKeyNote: 'يمكنك الدخول مباشرة. إن لم تكن لديك نسخة احتياطية من هذا المفتاح بعد، نزّلها.',
    btnUseOther: 'استخدام مفتاح آخر',
    importTitle: 'الصق مفتاحك',
    importHint: 'الصيغة: X39KEY-v1:…',
    importWarnReplace: 'تنبيه: سيستبدل هذا المفتاح الحالي على هذا الجهاز.',
    btnImportEnter: 'استيراد ودخول',
    back: 'رجوع',
  },
};

export default function Entrar() {
  const { user, setUser } = useAuth();
  const { lang } = useLang();
  const tt = (k) => (STR[lang] && STR[lang][k]) || STR.es[k] || k;
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const nextRaw = params.get('next') || '/panel';
  // Solo rutas internas: '/x'. Se rechaza '//host' (URL relativa a protocolo = redireccion externa).
  const next = nextRaw.startsWith('/') && !nextRaw.startsWith('//') ? nextRaw : '/panel';
  const [mode, setMode] = useState(hasKey() ? 'have' : 'choose');
  const [block, setBlock] = useState('');
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const [importText, setImportText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  if (user) return <Navigate to={next} replace />;

  const doLogin = async () => {
    setBusy(true);
    setError('');
    try {
      await login();
      const me = await api.me();
      setUser(me);
      navigate(next, { replace: true });
    } catch (e) {
      setError(e.message || 'Error');
      setBusy(false);
    }
  };

  const onCreate = () => {
    setError('');
    try {
      if (!hasKey()) createKey();
      setBlock(exportBlock());
      setSaved(false);
      setMode('backup');
    } catch (e) {
      setError(e.message || 'Error');
    }
  };

  const downloadKey = () => {
    const b = exportBlock();
    if (!b) return;
    const blob = new Blob([b + '\n'], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'x39-llave.txt';
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const copyKey = async () => {
    try {
      await navigator.clipboard.writeText(exportBlock() || '');
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* clipboard no disponible */ }
  };

  const onImport = async () => {
    setError('');
    try {
      importBlock(importText);
      await doLogin();
    } catch (e) {
      setError(e.message || 'Error');
      setBusy(false);
    }
  };

  const box = { maxWidth: 560, margin: '0 auto', padding: '48px 20px' };
  const warn = { border: '1px solid #CC0000', borderRadius: 8, padding: 14, margin: '14px 0' };
  const keyStyle = { wordBreak: 'break-all', padding: 12, border: '1px dashed #888', borderRadius: 8, margin: '12px 0' };

  return (
    <div className="nt">
      <div style={box}>
        <h1>{tt('title')}</h1>
        <p className="nt-note">{tt('intro')}</p>
        {error && <div className="nt-note nt-mono" style={warn} data-testid="entrar-error">{error}</div>}

        {mode === 'choose' && (
          <div>
            <button className="nt-btn nt-btn-primary" onClick={onCreate} disabled={busy} data-testid="entrar-create-btn">
              {tt('btnCreate')}
            </button>
            <div style={{ height: 10 }} />
            <button className="nt-btn" onClick={() => { setError(''); setMode('import'); }} disabled={busy} data-testid="entrar-have-btn">
              {tt('btnHaveKey')}
            </button>
          </div>
        )}

        {mode === 'backup' && (
          <div>
            <h2>{tt('backupTitle')}</h2>
            <div style={warn}>{tt('backupWarn')}</div>
            <div className="nt-mono" style={keyStyle} data-testid="entrar-key-block">{block}</div>
            <button className="nt-btn" onClick={downloadKey} data-testid="entrar-download-btn">{tt('btnDownload')}</button>{' '}
            <button className="nt-btn" onClick={copyKey} data-testid="entrar-copy-btn">{copied ? tt('copied') : tt('btnCopy')}</button>
            <div style={{ margin: '16px 0' }}>
              <label>
                <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} data-testid="entrar-saved-check" />{' '}
                {tt('savedCheck')}
              </label>
            </div>
            <button className="nt-btn nt-btn-primary" onClick={doLogin} disabled={!saved || busy} data-testid="entrar-enter-btn">
              {tt('btnEnter')}
            </button>
          </div>
        )}

        {mode === 'have' && (
          <div>
            <h2>{tt('haveKeyTitle')}</h2>
            <p className="nt-note">{tt('haveKeyNote')}</p>
            <button className="nt-btn nt-btn-primary" onClick={doLogin} disabled={busy} data-testid="entrar-enter-btn">
              {tt('btnEnter')}
            </button>
            <div style={{ height: 10 }} />
            <button className="nt-btn" onClick={downloadKey} data-testid="entrar-download-btn">{tt('btnDownload')}</button>{' '}
            <button className="nt-btn" onClick={() => { setError(''); setMode('import'); }} disabled={busy} data-testid="entrar-other-btn">
              {tt('btnUseOther')}
            </button>
          </div>
        )}

        {mode === 'import' && (
          <div>
            <h2>{tt('importTitle')}</h2>
            {hasKey() && <div style={warn}>{tt('importWarnReplace')}</div>}
            <textarea
              className="nt-mono"
              style={{ width: '100%', minHeight: 90 }}
              placeholder={tt('importHint')}
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              data-testid="entrar-import-text"
            />
            <div style={{ height: 10 }} />
            <button className="nt-btn nt-btn-primary" onClick={onImport} disabled={busy || !importText.trim()} data-testid="entrar-import-btn">
              {tt('btnImportEnter')}
            </button>{' '}
            <button className="nt-btn" onClick={() => { setError(''); setMode(hasKey() ? 'have' : 'choose'); }} disabled={busy} data-testid="entrar-back-btn">
              {tt('back')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
