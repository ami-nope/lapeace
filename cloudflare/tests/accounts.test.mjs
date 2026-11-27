import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeUsername,
  publicAccount,
  validAccessWindow,
  validOptionalInteger,
  validOptionalRate,
  validScryptHash,
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
    peerId: "a".repeat(64),
    note: "",
    status: "active",
    dailyQuotaBytes: null,
    monthlyQuotaBytes: null,
    uploadLimitMbps: null,
    downloadLimitMbps: null,
    maxConcurrentConnections: null,
    accessWindow: null,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
  };

  assert.equal(validScryptHash(account.passwordHash), true);
  const result = publicAccount(account);
  assert.equal("passwordHash" in result, false);
  assert.equal("normalizedUsername" in result, false);
  assert.equal(result.peerId, account.peerId);
});
