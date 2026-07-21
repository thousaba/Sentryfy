import type { Severity } from '../types/Alert';

interface SeverityMeta {
  label: string;
  color: string;
  track: string;
}


export const SEVERITY: Record<Severity, SeverityMeta> = {
  critical: { label: 'Critical',  color: '#e66767', track: 'rgba(230, 103, 103, 0.18)' },
  high:     { label: 'High',  color: '#ec835a', track: 'rgba(236, 131, 90, 0.18)'  },
  medium:   { label: 'Medium',    color: '#fab219', track: 'rgba(250, 178, 25, 0.18)'  },
  low:      { label: 'Low',   color: '#0ca30c', track: 'rgba(12, 163, 12, 0.18)'   },
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];
