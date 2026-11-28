export const USAGE_TIME_ZONE = "Asia/Kolkata";

export type UsageAssignment = {
  peerId: string;
  assignedAt: string;
  startUploadBytes: number;
  startDownloadBytes: number;
  endedAt?: string;
  endUploadBytes?: number;
  endDownloadBytes?: number;
};

export type UsageBaseline = {
  peerId: string;
  sampledAt: string;
  uploadBytes: number;
  downloadBytes: number;
};

export type PeerUsageDay = {
  date: string;
  uploadBytes: number;
  downloadBytes: number;
};

export type UsagePeer = {
  id: string;
  todayBytes: number;
  dailyUploadBytes: number;
  dailyDownloadBytes: number;
  rxBps: number;
  txBps: number;
  usageHistory: PeerUsageDay[];
};

export type UsageSnapshot = {
  sampledAt: string;
  historyStartDate: string | null;
  historyEndDate: string | null;
  peers: UsagePeer[];
};

export type AccountUsage = {
  sampledAt: string;
  todayUploadBytes: number;
  todayDownloadBytes: number;
  todayBytes: number;
  monthlyUploadBytes: number;
  monthlyDownloadBytes: number;
  monthlyBytes: number;
  dailyQuotaBytes: number | null;
  dailyRemainingBytes: number | null;
  monthlyQuotaBytes: number | null;
  monthlyRemainingBytes: number | null;
  uploadBps: number;
  downloadBps: number;
};

export class UsageTelemetryUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageTelemetryUnavailableError";
  }
}

export function isUsageAssignment(value: unknown): value is UsageAssignment {
  if (
    typeof value !== "object" ||
    value === null ||
    !("peerId" in value) ||
    typeof value.peerId !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.peerId) ||
    !("assignedAt" in value) ||
    typeof value.assignedAt !== "string" ||
    Number.isNaN(Date.parse(value.assignedAt)) ||
    !("startUploadBytes" in value) ||
    !isNonNegativeSafeInteger(value.startUploadBytes) ||
    !("startDownloadBytes" in value) ||
    !isNonNegativeSafeInteger(value.startDownloadBytes)
  ) {
    return false;
  }
  const endedAt = "endedAt" in value ? value.endedAt : undefined;
  const endUploadBytes =
    "endUploadBytes" in value ? value.endUploadBytes : undefined;
  const endDownloadBytes =
    "endDownloadBytes" in value ? value.endDownloadBytes : undefined;
  if (endedAt === undefined) {
    return endUploadBytes === undefined && endDownloadBytes === undefined;
  }
  return (
    typeof endedAt === "string" &&
    !Number.isNaN(Date.parse(endedAt)) &&
    isNonNegativeSafeInteger(endUploadBytes) &&
    isNonNegativeSafeInteger(endDownloadBytes)
  );
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function isDate(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return false;
  }
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

function isUsagePeer(value: unknown): value is UsagePeer {
  if (typeof value !== "object" || value === null) return false;
  if (
    !("id" in value) ||
    typeof value.id !== "string" ||
    !("todayBytes" in value) ||
    !isNonNegativeSafeInteger(value.todayBytes) ||
    !("dailyUploadBytes" in value) ||
    !isNonNegativeSafeInteger(value.dailyUploadBytes) ||
    !("dailyDownloadBytes" in value) ||
    !isNonNegativeSafeInteger(value.dailyDownloadBytes) ||
    !("rxBps" in value) ||
    typeof value.rxBps !== "number" ||
    !Number.isFinite(value.rxBps) ||
    value.rxBps < 0 ||
    !("txBps" in value) ||
    typeof value.txBps !== "number" ||
    !Number.isFinite(value.txBps) ||
    value.txBps < 0 ||
    !("usageHistory" in value) ||
    !Array.isArray(value.usageHistory)
  ) {
    return false;
  }
  return value.usageHistory.every(
    (entry) =>
      typeof entry === "object" &&
      entry !== null &&
      "date" in entry &&
      isDate(entry.date) &&
      "uploadBytes" in entry &&
      isNonNegativeSafeInteger(entry.uploadBytes) &&
      "downloadBytes" in entry &&
      isNonNegativeSafeInteger(entry.downloadBytes),
  );
}

export function isUsageSnapshot(value: unknown): value is UsageSnapshot {
  if (
    typeof value !== "object" ||
    value === null ||
    !("sampledAt" in value) ||
    typeof value.sampledAt !== "string" ||
    Number.isNaN(Date.parse(value.sampledAt)) ||
    !("historyStartDate" in value) ||
    !(value.historyStartDate === null || isDate(value.historyStartDate)) ||
    !("historyEndDate" in value) ||
    !(value.historyEndDate === null || isDate(value.historyEndDate)) ||
    !("peers" in value) ||
    !Array.isArray(value.peers)
  ) {
    return false;
  }
  return value.peers.every(isUsagePeer);
}

export function istDate(value: string | Date): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new UsageTelemetryUnavailableError("Telemetry has an invalid timestamp.");
  }
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: USAGE_TIME_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(date);
  const part = (type: string) => parts.find((item) => item.type === type)?.value;
  const year = part("year");
  const month = part("month");
  const day = part("day");
  if (!year || !month || !day) {
    throw new UsageTelemetryUnavailableError("Could not determine the IST date.");
  }
  return `${year}-${month}-${day}`;
}

function previousDate(value: string): string {
  const utc = new Date(`${value}T00:00:00.000Z`);
  utc.setUTCDate(utc.getUTCDate() - 1);
  return utc.toISOString().slice(0, 10);
}

function assignmentEndDate(assignment: UsageAssignment): string | null {
  return assignment.endedAt ? istDate(assignment.endedAt) : null;
}

function clippedDirection(
  total: number,
  assignment: UsageAssignment,
  day: string,
  direction: "upload" | "download",
): number {
  const start =
    direction === "upload"
      ? assignment.startUploadBytes
      : assignment.startDownloadBytes;
  const end =
    direction === "upload"
      ? assignment.endUploadBytes
      : assignment.endDownloadBytes;
  const lower = istDate(assignment.assignedAt) === day ? start : 0;
  let upper = total;
  if (day === assignmentEndDate(assignment)) {
    if (end === undefined || end === null || !isNonNegativeSafeInteger(end)) {
      throw new UsageTelemetryUnavailableError(
        "Assignment end counters are unavailable.",
      );
    }
    upper = Math.min(upper, end);
  }
  return Math.max(0, upper - lower);
}

function addSafe(total: number, value: number): number {
  const next = total + value;
  if (!Number.isSafeInteger(next)) {
    throw new UsageTelemetryUnavailableError("Usage total exceeds safe limits.");
  }
  return next;
}

export function calculateAccountUsage({
  assignments,
  snapshot,
  now = new Date(),
  dailyQuotaBytes,
  monthlyQuotaBytes,
}: {
  assignments: UsageAssignment[];
  snapshot: UsageSnapshot;
  now?: Date;
  dailyQuotaBytes: number | null;
  monthlyQuotaBytes: number | null;
}): AccountUsage {
  const today = istDate(now);
  if (istDate(snapshot.sampledAt) !== today) {
    throw new UsageTelemetryUnavailableError(
      "Telemetry does not contain a sample from the current IST day.",
    );
  }
  const monthStart = `${today.slice(0, 7)}-01`;
  const currentMonthAssignments = assignments.filter((assignment) => {
    const startDate = istDate(assignment.assignedAt);
    const endDate = assignmentEndDate(assignment);
    return startDate <= today && (!endDate || endDate >= monthStart);
  });
  const requiredHistoryStart = currentMonthAssignments.reduce((earliest, assignment) => {
    const startDate = istDate(assignment.assignedAt);
    const relevantStart = startDate > monthStart ? startDate : monthStart;
    return relevantStart < earliest ? relevantStart : earliest;
  }, today);
  const yesterday = previousDate(today);
  if (requiredHistoryStart < today) {
    if (
      snapshot.historyStartDate === null ||
      snapshot.historyStartDate > requiredHistoryStart ||
      snapshot.historyEndDate === null ||
      snapshot.historyEndDate < yesterday
    ) {
      throw new UsageTelemetryUnavailableError(
        "Monthly telemetry history does not cover the current IST month.",
      );
    }
  }

  const peerMap = new Map(snapshot.peers.map((peer) => [peer.id, peer]));
  const todayTotals = { upload: 0, download: 0 };
  const monthTotals = { upload: 0, download: 0 };

  for (const assignment of assignments) {
    const startDate = istDate(assignment.assignedAt);
    const endDate = assignmentEndDate(assignment);
    if (startDate <= today && (!endDate || endDate >= today)) {
      const peer = peerMap.get(assignment.peerId);
      if (!peer && endDate !== today) {
        throw new UsageTelemetryUnavailableError(
          "Telemetry for the assigned peer is unavailable.",
        );
      }
      const uploadTotal = peer?.dailyUploadBytes ?? assignment.endUploadBytes;
      const downloadTotal = peer?.dailyDownloadBytes ?? assignment.endDownloadBytes;
      if (
        uploadTotal === undefined ||
        uploadTotal === null ||
        downloadTotal === undefined ||
        downloadTotal === null
      ) {
        throw new UsageTelemetryUnavailableError(
          "Daily peer counters are unavailable.",
        );
      }
      todayTotals.upload = addSafe(
        todayTotals.upload,
        clippedDirection(uploadTotal, assignment, today, "upload"),
      );
      todayTotals.download = addSafe(
        todayTotals.download,
        clippedDirection(downloadTotal, assignment, today, "download"),
      );
    }

    const periodStart = startDate > monthStart ? startDate : monthStart;
    const periodEnd = endDate && endDate < today ? endDate : today;
    if (periodStart > periodEnd) continue;

    const peer = peerMap.get(assignment.peerId);
    if (!peer && periodStart < today) {
      throw new UsageTelemetryUnavailableError(
        "Telemetry history for an assigned peer is unavailable.",
      );
    }
    const historyByDate = new Map(
      (peer?.usageHistory ?? []).map((entry) => [entry.date, entry]),
    );
    for (let day = periodStart; day <= periodEnd; ) {
      let uploadTotal: number | null = null;
      let downloadTotal: number | null = null;
      if (day === today) {
        uploadTotal = peer?.dailyUploadBytes ?? assignment.endUploadBytes ?? null;
        downloadTotal = peer?.dailyDownloadBytes ?? assignment.endDownloadBytes ?? null;
      } else {
        const history = historyByDate.get(day);
        if (history) {
          uploadTotal = history.uploadBytes;
          downloadTotal = history.downloadBytes;
        } else if (peer) {
          uploadTotal = 0;
          downloadTotal = 0;
        }
      }
      if (uploadTotal === null || downloadTotal === null) {
        throw new UsageTelemetryUnavailableError(
          "Monthly peer telemetry is unavailable.",
        );
      }
      monthTotals.upload = addSafe(
        monthTotals.upload,
        clippedDirection(uploadTotal, assignment, day, "upload"),
      );
      monthTotals.download = addSafe(
        monthTotals.download,
        clippedDirection(downloadTotal, assignment, day, "download"),
      );
      const next = new Date(`${day}T00:00:00.000Z`);
      next.setUTCDate(next.getUTCDate() + 1);
      day = next.toISOString().slice(0, 10);
    }
  }

  const todayBytes = addSafe(todayTotals.upload, todayTotals.download);
  const monthlyBytes = addSafe(monthTotals.upload, monthTotals.download);
  return {
    sampledAt: snapshot.sampledAt,
    todayUploadBytes: todayTotals.upload,
    todayDownloadBytes: todayTotals.download,
    todayBytes,
    monthlyUploadBytes: monthTotals.upload,
    monthlyDownloadBytes: monthTotals.download,
    monthlyBytes,
    dailyQuotaBytes,
    dailyRemainingBytes:
      dailyQuotaBytes === null ? null : Math.max(0, dailyQuotaBytes - todayBytes),
    monthlyQuotaBytes,
    monthlyRemainingBytes:
      monthlyQuotaBytes === null
        ? null
        : Math.max(0, monthlyQuotaBytes - monthlyBytes),
    uploadBps:
      assignments.reduce((total, assignment) => {
        const peer = peerMap.get(assignment.peerId);
        return peer && !assignment.endedAt ? total + peer.rxBps : total;
      }, 0),
    downloadBps:
      assignments.reduce((total, assignment) => {
        const peer = peerMap.get(assignment.peerId);
        return peer && !assignment.endedAt ? total + peer.txBps : total;
      }, 0),
  };
}
