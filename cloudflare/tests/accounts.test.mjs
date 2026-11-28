import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeUsername,
  isPeerAssignedToAnotherAccount,
  publicAccount,
  reassignUsagePeriods,
  validAssignmentBoundary,
  validAccessWindow,
  validOptionalInteger,
  validOptionalRate,
  validScryptHash,
  validUsageBaseline,
  validUsername,
} from "../src/accounts.ts";

test("usernames are normalized for uniqueness and constrained to safe identifiers", () => {
  assert.equal(normalizeUsername("  Ami_User  "), "ami_user");
  assert.equal(validUsername("ami_user"), true);
  assert.equal(validUsername("ab"), false);
  assert.equal(validUsername("../admin"), false);
});

test("account policy fields reject invalid limits and time zones", () => {
  assert.equal(validOptionalInteger(null, 100), true);
  assert.equal(validOptionalInteger(100, 100), true);
  assert.equal(validOptionalInteger(0, 100), false);
  assert.equal(validOptionalInteger(101, 100), false);
  assert.equal(validOptionalRate(25.5), true);
  assert.equal(validOptionalRate(Infinity), false);
  assert.equal(
    validAccessWindow({
      start: "09:00",
      end: "17:30",
      timeZone: "Asia/Kolkata",
    }),
    true,
  );
  assert.equal(
    validAccessWindow({
      start: "25:00",
      end: "17:30",
      timeZone: "Asia/Kolkata",
    }),
    false,
  );
  assert.equal(
    validAccessWindow({ start: "09:00", end: "17:30", timeZone: "Mars/Base" }),
    false,
  );
});

test("public account records never contain password hashes or normalized IDs", () => {
  const account = {
    id: "00000000-0000-4000-8000-000000000001",
    username: "test_user",
    normalizedUsername: "test_user",
    passwordHash: `scrypt:${"a".repeat(32)}:${"b".repeat(128)}`,
    authVersion: 0,
    peerId: "a".repeat(64),
    note: "",
    status: "active",
    dailyQuotaBytes: null,
    monthlyQuotaBytes: null,
    uploadLimitMbps: null,
    downloadLimitMbps: null,
    maxConcurrentConnections: null,
    accessWindow: null,
    usageAssignments: [{
      peerId: "a".repeat(64),
      assignedAt: "2026-01-01T00:00:00.000Z",
      startUploadBytes: 10,
      startDownloadBytes: 20,
    }],
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
  };

  assert.equal(validScryptHash(account.passwordHash), true);
  const result = publicAccount(account);
  assert.equal("passwordHash" in result, false);
  assert.equal("normalizedUsername" in result, false);
  assert.equal("authVersion" in result, false);
  assert.equal("usageAssignments" in result, false);
  assert.equal(result.peerId, account.peerId);
});

test("assignment baselines and reassignment boundaries require safe counters", () => {
  const baseline = {
    peerId: "a".repeat(64),
    sampledAt: "2026-01-01T00:00:00.000Z",
    uploadBytes: 100,
    downloadBytes: 200,
  };
  assert.equal(validUsageBaseline(baseline), true);
  assert.equal(validUsageBaseline({ ...baseline, uploadBytes: -1 }), false);
  assert.equal(validUsageBaseline({ ...baseline, peerId: "invalid" }), false);
  assert.equal(
    validAssignmentBoundary({
      sampledAt: baseline.sampledAt,
      previousUploadBytes: 100,
      previousDownloadBytes: 200,
      nextUploadBytes: 300,
      nextDownloadBytes: 400,
    }),
    true,
  );
  assert.equal(
    validAssignmentBoundary({
      sampledAt: baseline.sampledAt,
      previousUploadBytes: Number.MAX_SAFE_INTEGER + 1,
      previousDownloadBytes: 200,
      nextUploadBytes: 300,
      nextDownloadBytes: 400,
    }),
    false,
  );
});

test("peer ownership is unique and reassignment preserves the closed usage period", () => {
  const peerA = "a".repeat(64);
  const peerB = "b".repeat(64);
  const accounts = [
    { id: "account-a", peerId: peerA },
    { id: "account-b", peerId: peerB },
  ];
  assert.equal(isPeerAssignedToAnotherAccount(accounts, peerA), true);
  assert.equal(isPeerAssignedToAnotherAccount(accounts, peerA, "account-a"), false);

  const original = [{
    peerId: peerA,
    assignedAt: "2026-01-01T00:00:00.000Z",
    startUploadBytes: 10,
    startDownloadBytes: 20,
  }];
  const boundary = {
    sampledAt: "2026-01-02T00:00:00.000Z",
    previousUploadBytes: 50,
    previousDownloadBytes: 70,
    nextUploadBytes: 300,
    nextDownloadBytes: 400,
  };
  const periods = reassignUsagePeriods(original, peerA, peerB, boundary);
  assert.equal(original[0].endedAt, undefined);
  assert.deepEqual(periods[0], {
    ...original[0],
    endedAt: boundary.sampledAt,
    endUploadBytes: 50,
    endDownloadBytes: 70,
  });
  assert.deepEqual(periods[1], {
    peerId: peerB,
    assignedAt: boundary.sampledAt,
    startUploadBytes: 300,
    startDownloadBytes: 400,
  });
  assert.equal(
    isPeerAssignedToAnotherAccount(
      [{ id: "account-a", peerId: peerB }, { id: "account-b", peerId: peerA }],
      peerA,
      "account-b",
    ),
    false,
  );
  assert.equal(
    isPeerAssignedToAnotherAccount(
      [{ id: "account-a", peerId: peerB }, { id: "account-c", peerId: peerB }],
      peerB,
      "account-c",
    ),
    true,
  );
});
