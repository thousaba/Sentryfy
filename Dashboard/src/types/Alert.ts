export interface Alert {
  timestamp: string;
  rule: {
    id: string;
    level: number;
    description: string;
  };
  agent: {
    id: string;
    name: string;
    ip: string;
  };
  data?: {
    srcip?: string;
    win?: {
      eventdata?: {
        ipAddress?: string;
      };
    };
  };
}
