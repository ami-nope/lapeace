export type AccountStatus = "active" | "suspended";

export type AccessWindow = {
  start: string;
  end: string;
  timeZone: string;
};

export type PortalAccount = {
  id: string;
  username: string;
  peerId: string;
  note: string;
  status: AccountStatus;
  dailyQuotaBytes: number | null;
  monthlyQuotaBytes: number | null;
  uploadLimitMbps: number | null;
  downloadLimitMbps: number | null;
  maxConcurrentConnections: number | null;
  accessWindow: AccessWindow | null;
  createdAt: string;
  updatedAt: string;
};

export type AuditRecord = {
  id: string;
  at: string;
  action: string;
  subject: string;
};
