import type { CSSProperties } from 'react';
import '../css/StatTile.css';

interface StatTileProps {
  label: string;
  value: number;
  color?: string;
}

function StatTile({ label, value, color }: StatTileProps) {
  return (
    <div className="stat-tile" style={color ? ({ '--accent': color } as CSSProperties) : undefined}>
      <span className="stat-tile-value">{value}</span>
      <span className="stat-tile-label">{label}</span>
    </div>
  );
}

export default StatTile;
