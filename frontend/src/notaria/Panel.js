import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Plus, ChevronRight } from 'lucide-react';
import { Nav } from './Nav';
import { useAuth } from './NotariaApp';
import { useLang } from './i18n';
import { api } from './api';

const Badge = ({ status, ots, t }) => {
  if (status !== 'sealed') return <span className="nt-badge nt-badge-pending">{t('panel.badgePending')}</span>;
  if (ots?.status === 'anchored_btc') return <span className="nt-badge nt-badge-sealed">{t('panel.badgeConfirmed')}{ots.btc_block}</span>;
  return <span className="nt-badge nt-badge-draft">{t('panel.badgeSealedPending')}</span>;
};

export default function Panel() {
  const { user } = useAuth();
  const { t } = useLang();
  const [rows, setRows] = useState(null);

  useEffect(() => {
    api.listAgreements().then(setRows).catch(() => setRows([]));
  }, []);

  return (
    <div data-testid="panel-page">
      <Nav />
      <main className="nt-wrap" style={{ padding: '40px 20px 80px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 16, marginBottom: 32 }}>
          <div>
            <div className="nt-label">{t('panel.kicker')}</div>
            <h1 className="nt-serif" style={{ fontSize: 36, fontWeight: 600, margin: 0 }}>{t('panel.title')}</h1>
            <div className="nt-note nt-mono" style={{ marginTop: 6 }} data-testid="panel-user-email">{user?.email}</div>
          </div>
          <Link to="/crear" className="nt-btn nt-btn-seal" data-testid="panel-new-agreement-btn">
            <Plus size={16} strokeWidth={2} /> {t('panel.new')}
          </Link>
        </div>

        {rows === null && <div className="nt-note nt-mono">{t('common.loading')}</div>}

        {rows?.length === 0 && (
          <div className="nt-card nt-card-pad" style={{ textAlign: 'center' }} data-testid="panel-empty">
            <p className="nt-serif" style={{ fontSize: 22, margin: '0 0 6px' }}>{t('panel.emptyTitle')}</p>
            <p className="nt-note" style={{ margin: '0 0 20px' }}>{t('panel.emptyBody')}</p>
            <Link to="/crear" className="nt-btn nt-btn-primary" data-testid="panel-empty-create-btn">{t('panel.emptyCta')}</Link>
          </div>
        )}

        <div className="nt-list">
          {rows?.map((a) => (
            <Link to={`/acuerdo/${a.agreement_id}`} className="nt-agreement-row" key={a.agreement_id} data-testid={`agreement-row-${a.agreement_id}`}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</div>
                <div className="nt-note nt-mono" style={{ fontSize: 11 }}>
                  {a.party_a}{a.party_b ? ` · ${a.party_b}` : ` · ${t('panel.waitingOther')}`}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
                <Badge status={a.status} ots={a.ots} t={t} />
                <ChevronRight size={16} strokeWidth={1.5} color="var(--muted)" />
              </div>
            </Link>
          ))}
        </div>
      </main>
    </div>
  );
}
