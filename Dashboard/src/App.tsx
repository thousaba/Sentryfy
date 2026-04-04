import './App.css';
import { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import AlertCard from './components/AlertCard';
import type { Alert } from './types/Alert';

const socket = io('http://localhost:3000');

function App() {
  const [alerts, setAlerts] = useState<Alert[]>(() => {
    const saved = localStorage.getItem('sentryfy-alerts');
    return saved ? JSON.parse(saved) : [];
  });

  // alerts değişince kaydet
  useEffect(() => {
    localStorage.setItem('sentryfy-alerts', JSON.stringify(alerts));
  }, [alerts]);

  useEffect(() => {
    socket.on('connect', () => {
      console.log('🔌 Backend ile bağlantı kuruldu!');
    });

    socket.on('new-alert', (alert: Alert) => {
      console.log('🚨 Yeni alert geldi:', alert);
      setAlerts(prev => [alert, ...prev]);
    });

    return () => {
      socket.off('new-alert');
    };
  }, []);

  return (
    <div className="app-container">
      <h1>WAZUH LOGS</h1>
      <input className="search-bar" type="text" placeholder="Loglarda ara..." />
      <p>Canlı Alertler: {alerts.length}</p>

      <div className="alerts-scroll">
        {alerts.map((alert, index) => (
          <AlertCard key={index} alert={alert} onDelete={() => setAlerts(prev => prev.filter((_, i) => i !== index))} />
        ))}

        {alerts.length === 0 && <p>Henüz alert yok, bekliyoruz... 👀</p>}
      </div>
    </div>
  );
}

export default App;
