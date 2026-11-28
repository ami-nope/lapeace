import assert from "node:assert/strict";
import test from "node:test";
import {
  calculateAccountUsage,
  UsageTelemetryUnavailableError,
} from "../lib/usage-accounting.ts";

const GIB = 1024 ** 3;

function peer(id, upload, download, usageHistory = []) {
  return {
    id,
    todayBytes: upload + download,
    dailyUploadBytes: upload,
    dailyDownloadBytes: download,
    rxBps: 0,
    txBps: 0,
    usageHistory,
  };
}

function snapshot(sampledAt, peers, historyStartDate, historyEndDate) {
  return { sampledAt, peers, historyStartDate, historyEndDate };
}

function assignment(peerId, assignedAt, upload, download, end = undefined) {
  return {
    peerId,
    assignedAt,
    startUploadBytes: upload,
    startDownloadBytes: download,
    ...(end ? {
      endedAt: end.at,
      endUploadBytes: end.upload,
      endDownloadBytes: end.download,
    } : {}),
  };
}

function usage(assignments, current, currentAt, historyStart, historyEnd, quotas = {}) {
  return calculateAccountUsage({
    assignments,
    snapshot: snapshot(currentAt, current, historyStart, historyEnd),
    now: new Date(currentAt),
    dailyQuotaBytes: quotas.daily ?? null,
    monthlyQuotaBytes: quotas.monthly ?? null,
  });
}

test("assignment halfway through an IST day charges only later traffic", () => {
  const result = usage(
    [assignment("peer-a", "2026-11-27T06:30:00.000Z", 2_000, 1_000)],
    [peer("peer-a", 5_000, 3_000, [
      { date: "2026-11-27", uploadBytes: 5_000, downloadBytes: 3_000 },
    ])],
    "2026-11-27T10:00:00.000Z",
    "2026-11-01",
    "2026-11-27",
  );
  assert.equal(result.todayUploadBytes, 3_000);
  assert.equal(result.todayDownloadBytes, 2_000);
  assert.equal(result.todayBytes, 5_000);
});

test("several GB of peer traffic before account creation is excluded", () => {
  const result = usage(
    [assignment("peer-a", "2026-11-27T06:30:00.000Z", 5 * GIB, 2 * GIB)],
    [peer("peer-a", 5 * GIB + GIB / 4, 2 * GIB + GIB / 8)],
    "2026-11-27T10:00:00.000Z",
    "2026-11-01",
    "2026-11-27",
  );
  assert.equal(result.todayUploadBytes, GIB / 4);
  assert.equal(result.todayDownloadBytes, GIB / 8);
});

test("daily baseline resets at IST midnight while monthly usage carries over", () => {
  const result = usage(
    [assignment("peer-a", "2026-11-27T18:20:00.000Z", 900, 450)],
    [peer("peer-a", 25, 15, [
      { date: "2026-11-27", uploadBytes: 1_000, downloadBytes: 500 },
      { date: "2026-11-28", uploadBytes: 25, downloadBytes: 15 },
    ])],
    "2026-11-27T18:31:00.000Z",
    "2026-11-01",
    "2026-11-28",
  );
  assert.equal(result.todayBytes, 40);
  assert.equal(result.monthlyUploadBytes, 125);
  assert.equal(result.monthlyDownloadBytes, 65);
});

test("monthly usage starts over on the first day of a new IST month", () => {
  const result = usage(
    [assignment("peer-a", "2026-11-30T12:00:00.000Z", 1_000, 500)],
    [peer("peer-a", 300, 200, [
      { date: "2026-12-01", uploadBytes: 300, downloadBytes: 200 },
    ])],
    "2026-12-01T04:30:00.000Z",
    "2026-12-01",
    "2026-12-01",
  );
  assert.equal(result.todayBytes, 500);
  assert.equal(result.monthlyBytes, 500);
});

test("counter resets never create negative usage", () => {
  const result = usage(
    [assignment("peer-a", "2026-11-27T06:30:00.000Z", 1_000, 800)],
    [peer("peer-a", 400, 200)],
    "2026-11-27T10:00:00.000Z",
    "2026-11-27",
    "2026-11-27",
  );
  assert.equal(result.todayUploadBytes, 0);
  assert.equal(result.todayDownloadBytes, 0);
});

test("reassignment closes the prior period and starts a fresh peer baseline", () => {
  const result = usage(
    [
      assignment("peer-old", "2026-11-26T06:30:00.000Z", 30, 10, {
        at: "2026-11-27T06:30:00.000Z",
        upload: 250,
        download: 180,
      }),
      assignment("peer-new", "2026-11-27T06:30:00.000Z", 500, 200),
    ],
    [
      peer("peer-old", 300, 200, [
        { date: "2026-11-26", uploadBytes: 100, downloadBytes: 50 },
        { date: "2026-11-27", uploadBytes: 300, downloadBytes: 200 },
      ]),
      peer("peer-new", 800, 300, [
        { date: "2026-11-27", uploadBytes: 800, downloadBytes: 300 },
      ]),
    ],
    "2026-11-27T10:00:00.000Z",
    "2026-11-01",
    "2026-11-27",
  );
  assert.equal(result.todayUploadBytes, 550);
  assert.equal(result.todayDownloadBytes, 280);
  assert.equal(result.monthlyUploadBytes, 620);
  assert.equal(result.monthlyDownloadBytes, 320);
});

test("missing assigned-peer telemetry is unavailable rather than zero", () => {
  assert.throws(
    () => usage(
      [assignment("peer-missing", "2026-11-27T06:30:00.000Z", 0, 0)],
      [],
      "2026-11-27T10:00:00.000Z",
      "2026-11-27",
      "2026-11-27",
    ),
    UsageTelemetryUnavailableError,
  );
});

test("daily and monthly quotas remain independent and never report negative remaining", () => {
  const result = usage(
    [assignment("peer-a", "2026-11-26T06:30:00.000Z", 500, 200)],
    [peer("peer-a", 800, 400, [
      { date: "2026-11-26", uploadBytes: 700, downloadBytes: 300 },
      { date: "2026-11-27", uploadBytes: 800, downloadBytes: 400 },
    ])],
    "2026-11-27T10:00:00.000Z",
    "2026-11-01",
    "2026-11-27",
    { daily: 1_000, monthly: 1_400 },
  );
  assert.equal(result.todayBytes, 1_200);
  assert.equal(result.dailyRemainingBytes, 0);
  assert.equal(result.monthlyBytes, 1_500);
  assert.equal(result.monthlyRemainingBytes, 0);
});

test("accounts assigned different peers receive independent totals", () => {
  const current = [
    peer("peer-a", 100, 50),
    peer("peer-b", 700, 300),
  ];
  const sharedSnapshot = snapshot(
    "2026-11-27T10:00:00.000Z",
    current,
    "2026-11-27",
    "2026-11-27",
  );
  const first = calculateAccountUsage({
    assignments: [assignment("peer-a", "2026-11-27T06:30:00.000Z", 20, 10)],
    snapshot: sharedSnapshot,
    now: new Date("2026-11-27T10:00:00.000Z"),
    dailyQuotaBytes: null,
    monthlyQuotaBytes: null,
  });
  const second = calculateAccountUsage({
    assignments: [assignment("peer-b", "2026-11-27T06:30:00.000Z", 100, 100)],
    snapshot: sharedSnapshot,
    now: new Date("2026-11-27T10:00:00.000Z"),
    dailyQuotaBytes: null,
    monthlyQuotaBytes: null,
  });
  assert.equal(first.todayBytes, 120);
  assert.equal(second.todayBytes, 800);
});
