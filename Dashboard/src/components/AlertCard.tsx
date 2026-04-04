import type { Alert } from '../types/Alert'
import '../css/Alert.css';
import { FaTrashAlt } from "react-icons/fa";

interface AlertCardProps {
  alert: Alert;
  onDelete: () => void;
}

function resolveIp(alert: Alert): string {
  const rawIp = alert.data?.win?.eventdata?.ipAddress;
  const agentIp = alert.agent?.ip;

  if (!rawIp || rawIp === '-' || rawIp === '::1' || rawIp === '0.0.0.0') {
    return agentIp ? `Yerel (${agentIp})` : 'Bilinmiyor';
  }
  return rawIp;
}

function formatTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

function AlertCard({ alert, onDelete }: AlertCardProps) {
  const ip = resolveIp(alert);

  return (
    <div className='alert-card'>
      <button className="delete-btn" onClick={onDelete}>
        <FaTrashAlt />
      </button>
      <p>🚨 <b>{alert.rule.description}</b></p>
      <p>Seviye: {alert.rule.level}</p>
      <p>Ajan: {alert.agent.name}</p>
      <p>IP: {ip}</p>
      <p>Zaman: {formatTime(alert.timestamp)}</p>
    </div>
  );
}

export default AlertCard;
