import type { CSSProperties } from 'react';
import type { Severity } from '../types/Alert';
import { SEVERITY } from '../lib/severity';
import '../css/RiskMeter.css';

interface RiskMeterProps {
  score:    number; // 0-100
  severity: Severity;
}

function RiskMeter({ score, severity }: RiskMeterProps) {
  const meta = SEVERITY[severity];
  const pct  = Math.max(0, Math.min(100, score));

  return (
    <div className="risk-meter">
      <div
        className="risk-meter-track"
        style={{ '--fill-color': meta.color, '--track-color': meta.track } as CSSProperties}
      >
        <div className="risk-meter-fill" style={{ width: `${pct}%` }} />
      </div>
      <span className="risk-meter-value" style={{ color: meta.color }}>{score}</span>
    </div>
  );
}

export default RiskMeter;
