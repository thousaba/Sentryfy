import type { CSSProperties } from 'react';
import type { Severity } from '../types/Alert';
import { SEVERITY } from '../lib/severity';
import '../css/SeverityBadge.css';

function SeverityBadge({ severity }: { severity: Severity }) {
  const meta = SEVERITY[severity];
  return (
    <span className="severity-badge" style={{ '--badge-color': meta.color } as CSSProperties}>
      <span className="severity-badge-dot" />
      {meta.label}
    </span>
  );
}

export default SeverityBadge;
