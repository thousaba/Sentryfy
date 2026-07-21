import './App.css';
import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import { io } from 'socket.io-client';
import AlertCard from './components/AlertCard';
import StatTile from './components/StatTile';
import type { RiskAlert, Severity } from './types/Alert';
import { SEVERITY, SEVERITY_ORDER } from './lib/severity';

const socket = io('http://localhost:3000');

type SeverityFilter = Severity | 'all';

function App() {
  const [alerts, setAlerts] = useState<RiskAlert[]>(() => {
    const saved = localStorage.getItem('sentryfy-risk-alerts');
    return saved ? JSON.parse(saved) : [];
  });
  const [connected, setConnected] = useState(false);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');

  useEffect(() => {
    localStorage.setItem('sentryfy-risk-alerts', JSON.stringify(alerts));
  }, [alerts]);

  useEffect(() => {
    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));

    socket.on('new-alert', (alert: RiskAlert) => {
      setAlerts(prev => {
        const idx = prev.findIndex(a => a.riskObject === alert.riskObject);
        if (idx === -1) return [alert, ...prev];
        const next = [...prev];
        next[idx] = alert;
        return next;
      });
    });

    return () => {
      socket.off('connect');
      socket.off('disconnect');
      socket.off('new-alert');
    };
  }, []);

  const counts = useMemo(() => {
    const base: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) base[a.severity]++;
    return base;
  }, [alerts]);

  const visibleAlerts = useMemo(() => {
    return alerts
      .filter(a => severityFilter === 'all' || a.severity === severityFilter)
      .filter(a => a.riskObject.toLowerCase().includes(search.toLowerCase()))
      .sort((a, b) => b.totalRisk - a.totalRisk);
  }, [alerts, severityFilter, search]);

  const deleteAlert = (riskObject: string) => {
    setAlerts(prev => prev.filter(a => a.riskObject !== riskObject));
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <div>
          <h1>SENTRYFY</h1>
          <p className="app-subtitle">Risk-Based Alerting</p>
        </div>
        <div className="live-indicator">
          <span className={`live-dot ${connected ? 'live-dot-on' : ''}`} />
          {connected ? 'Bağlı' : 'Bağlantı yok'}
        </div>
      </header>

      <div className="stats-row">
        <StatTile label="Toplam" value={alerts.length} />
        {SEVERITY_ORDER.map(sev => (
          <StatTile key={sev} label={SEVERITY[sev].label} value={counts[sev]} color={SEVERITY[sev].color} />
        ))}
      </div>

      <div className="filter-row">
        <input
          className="search-bar"
          type="text"
          placeholder="Risk objesi ara (host, kullanıcı...)"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <div className="severity-filter">
          <button
            className={`severity-filter-btn ${severityFilter === 'all' ? 'active' : ''}`}
            onClick={() => setSeverityFilter('all')}
          >
            All
          </button>
          {SEVERITY_ORDER.map(sev => (
            <button
              key={sev}
              className={`severity-filter-btn ${severityFilter === sev ? 'active' : ''}`}
              style={{ '--accent': SEVERITY[sev].color } as CSSProperties}
              onClick={() => setSeverityFilter(sev)}
            >
              {SEVERITY[sev].label}
            </button>
          ))}
        </div>
      </div>

      <div className="alerts-scroll">
        {visibleAlerts.map(alert => (
          <AlertCard key={alert.riskObject} alert={alert} onDelete={() => deleteAlert(alert.riskObject)} />
        ))}

        {visibleAlerts.length === 0 && (
          <p className="empty-state">Henüz alert yok, bekliyoruz... 👀</p>
        )}
      </div>
    </div>
  );
}

export default App;
