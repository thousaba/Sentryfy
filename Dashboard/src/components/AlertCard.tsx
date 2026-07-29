import type { CSSProperties } from 'react';
import { FaTrashAlt } from 'react-icons/fa';
import type { RiskAlert } from '../types/Alert';
import { SEVERITY } from '../lib/severity';
import SeverityBadge from './SeverityBadge';
import RiskMeter from './RiskMeter';
import '../css/Alert.css';

interface AlertCardProps {
  alert:    RiskAlert;
  onDelete: () => void;
}

function formatTime(ts: string): string {
  return new Date(ts).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function AlertCard({ alert, onDelete }: AlertCardProps) {
  const meta = SEVERITY[alert.severity];

  return (
    <div className="alert-card" style={{ '--accent': meta.color } as CSSProperties}>
      <button className="delete-btn" onClick={onDelete} aria-label="Sil">
        <FaTrashAlt />
      </button>

      <div className="alert-card-header">
        <div>
          <h3 className="alert-card-title">{alert.riskObject}</h3>
          {alert.title && <span className="alert-card-subtitle">{alert.title}</span>}
        </div>
        <SeverityBadge severity={alert.severity} />
      </div>

      <RiskMeter score={alert.totalRisk} severity={alert.severity} />

      {alert.description && (
        <p className="alert-card-description">{alert.description}</p>
      )}

      <div className="alert-card-meta">
        <span>{alert.detectionCount} detections</span>
        <span className="alert-card-meta-dot">•</span>
        <span>{alert.techniqueCount} techniques</span>
        <span className="alert-card-meta-dot">•</span>
        <span>{formatTime(alert.timestamp)}</span>
      </div>

      {alert.techniques.length > 0 && (
        <div className="chip-row">
          {alert.techniques.map((t, i) => (
            <span className="chip" key={`${t}-${i}`}>{t}</span>
          ))}
        </div>
      )}

      {alert.detections.length > 0 && (
        <ul className="detection-list">
          {alert.detections.map((d, i) => (
            <li key={`${d}-${i}`}>{d}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default AlertCard;
