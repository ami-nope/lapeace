export type AccountStatus = "active" | "suspended";

export interface AccessWindow {
  start: string;
  end: string;
  timeZone: string;
}

export interface UsageAssignment {
  peerId: string;
  assignedAt: string;
  startUploadBytes: number;
  startDownloadBytes: number;
  endedAt?: string;
  endUploadBytes?: number;
  endDownloadBytes?: number;
}

export interface UsageBaseline {
  peerId: string;
  sampledAt: string;
  uploadBytes: number;
  downloadBytes: number;
}

export interface AssignmentBoundary {
  sampledAt: string;
  previousUploadBytes: number;
  previousDownloadBytes: number;
  nextUploadBytes: number;
  nextDownloadBytes: number;
}

export interface AccountRecord {
  id: string;
  username: string;
  normalizedUsername: string;
  passwordHash: string;
  authVersion: number;
  peerId: string;
  note: string;
  status: AccountStatus;
  dailyQuotaBytes: number | null;
  monthlyQuotaBytes: number | null;
  uploadLimitMbps: number | null;
  downloadLimitMbps: number | null;
  maxConcurrentConnections: number | null;
  accessWindow: AccessWindow | null;
  usageAssignments: UsageAssignment[];
  createdAt: string;
  updatedAt: string;
}

export function isPeerAssignedToAnotherAccount(
  accounts: Iterable<Pick<AccountRecord, "id" | "peerId">>,
  peerId: string,
  accountId?: string,
): boolean {
  for (const account of accounts) {
    if (account.id !== accountId && account.peerId === peerId) return true;
  }
  return false;
}

export function reassignUsagePeriods(
  assignments: UsageAssignment[],
  previousPeerId: string,
  nextPeerId: string,
  boundary: AssignmentBoundary,
): UsageAssignment[] {
  const updated = [...assignments];
  let previousIndex = -1;
  for (let index = updated.length - 1; index >= 0; index -= 1) {
    const assignment = updated[index];
    if (assignment.peerId === previousPeerId && !assignment.endedAt) {
      previousIndex = index;
      break;
    }
  }
  if (previousIndex >= 0) {
    updated[previousIndex] = {
      ...updated[previousIndex],
      endedAt: boundary.sampledAt,
      endUploadBytes: boundary.previousUploadBytes,
      endDownloadBytes: boundary.previousDownloadBytes,
    };
  } else {
    updated.push({
      peerId: previousPeerId,
      assignedAt: boundary.sampledAt,
      startUploadBytes: boundary.previousUploadBytes,
      startDownloadBytes: boundary.previousDownloadBytes,
      endedAt: boundary.sampledAt,
      endUploadBytes: boundary.previousUploadBytes,
      endDownloadBytes: boundary.previousDownloadBytes,
    });
  }
  updated.push({
    peerId: nextPeerId,
    assignedAt: boundary.sampledAt,
    startUploadBytes: boundary.nextUploadBytes,
    startDownloadBytes: boundary.nextDownloadBytes,
  });
  return updated;
}

export type PublicAccount = Omit<
  AccountRecord,
  "normalizedUsername" | "passwordHash" | "authVersion" | "usageAssignments"
>;

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
  const {
    passwordHash: _passwordHash,
    normalizedUsername: _normalizedUsername,
    authVersion: _authVersion,
    usageAssignments: _usageAssignments,
    ...result
  } = record;
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

function validCounter(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function validSampledAt(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 64 &&
    !Number.isNaN(Date.parse(value))
  );
}

export function validUsageBaseline(value: unknown): value is UsageBaseline {
  return (
    typeof value === "object" &&
    value !== null &&
    "peerId" in value &&
    typeof value.peerId === "string" &&
    /^[a-f0-9]{64}$/.test(value.peerId) &&
    "sampledAt" in value &&
    validSampledAt(value.sampledAt) &&
    "uploadBytes" in value &&
    validCounter(value.uploadBytes) &&
    "downloadBytes" in value &&
    validCounter(value.downloadBytes)
  );
}

export function validAssignmentBoundary(
  value: unknown,
): value is AssignmentBoundary {
  return (
    typeof value === "object" &&
    value !== null &&
    "sampledAt" in value &&
    validSampledAt(value.sampledAt) &&
    "previousUploadBytes" in value &&
    validCounter(value.previousUploadBytes) &&
    "previousDownloadBytes" in value &&
    validCounter(value.previousDownloadBytes) &&
    "nextUploadBytes" in value &&
    validCounter(value.nextUploadBytes) &&
    "nextDownloadBytes" in value &&
    validCounter(value.nextDownloadBytes)
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
