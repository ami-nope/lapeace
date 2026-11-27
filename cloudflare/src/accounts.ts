export type AccountStatus = "active" | "suspended";

export interface AccessWindow {
  start: string;
  end: string;
  timeZone: string;
}

export interface AccountRecord {
  id: string;
  username: string;
  normalizedUsername: string;
  passwordHash: string;
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
}

export type PublicAccount = Omit<AccountRecord, "normalizedUsername" | "passwordHash">;

export function normalizeUsername(value: string): string {
  return value.trim().toLowerCase();
}

export function validUsername(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{2,47}$/.test(value);
}

export function validScryptHash(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^scrypt:[a-f0-9]{32}:[a-f0-9]{128}$/i.test(value)
  );
}

export function publicAccount(record: AccountRecord): PublicAccount {
  const { passwordHash: _passwordHash, normalizedUsername: _normalizedUsername, ...result } =
    record;
  return result;
}

export function validOptionalInteger(
  value: unknown,
  maximum: number,
): value is number | null {
  return (
    value === null ||
    (typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value > 0 &&
      value <= maximum)
  );
}

export function validOptionalRate(value: unknown): value is number | null {
  return (
    value === null ||
    (typeof value === "number" &&
      Number.isFinite(value) &&
      value > 0 &&
      value <= 10_000)
  );
}

export function validAccessWindow(value: unknown): value is AccessWindow | null {
  if (value === null) return true;
  if (
    typeof value !== "object" ||
    value === null ||
    !("start" in value) ||
    !("end" in value) ||
    !("timeZone" in value) ||
    typeof value.start !== "string" ||
    typeof value.end !== "string" ||
    typeof value.timeZone !== "string" ||
    !/^([01]\d|2[0-3]):[0-5]\d$/.test(value.start) ||
    !/^([01]\d|2[0-3]):[0-5]\d$/.test(value.end) ||
    value.timeZone.length > 64
  ) {
    return false;
  }
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value.timeZone });
  } catch {
    return false;
  }
  return true;
}
