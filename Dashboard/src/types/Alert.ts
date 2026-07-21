export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface RiskAlert {
  id:             string;
  timestamp:      string;
  riskObject:     string;
  totalRisk:      number;
  severity:       Severity;
  detectionCount: number;
  detections:     string[];
  techniqueCount: number;
  techniques:     string[];
}
