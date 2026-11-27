import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import {
  isExpired,
  isPublicIpv4,
  registerRecord,
  readSessionClaims,
  verifyAdminSession,
} from "../src/core.ts";

test("public IPv4 validation rejects private, reserved, and malformed values", () => {
  for (const address of [
    "10.0.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "172.16.0.1",
    "192.168.1.1",
    "192.88.99.1",
    "198.18.0.1",
    "224.0.0.1",
    "240.0.0.1",
    "192.0.2.1",
    "8.008.8.8",
    "8.8.8",
    "not-an-ip",
  ]) {
    assert.equal(isPublicIpv4(address), false, address);
  }
  assert.equal(isPublicIpv4("8.8.8.8"), true);
  assert.equal(isPublicIpv4("1.1.1.1"), true);
});

test("re-registration preserves first registration and updates last used", () => {
  const previous = {
    ip: "8.8.8.8",
    firstRegisteredAt: "2026-01-01T00:00:00.000Z",
    lastUsedAt: "2026-01-02T00:00:00.000Z",
    registrationSource: "cloudflare-edge",
    status: "expired",
  };
  const updated = registerRecord(
    previous,
    "8.8.8.8",
    "2026-11-27T12:00:00.000Z",
    "cloudflare-edge",
  );

  assert.equal(updated.firstRegisteredAt, previous.firstRegisteredAt);
  assert.equal(updated.lastUsedAt, "2026-11-27T12:00:00.000Z");
  assert.equal(updated.status, "active");
});

test("expiration applies only after fifteen complete days", () => {
  const now = Date.parse("2026-11-27T12:00:00.000Z");
  assert.equal(isExpired("2026-11-12T12:00:00.000Z", now), false);
  assert.equal(isExpired("2026-11-12T11:59:59.999Z", now), true);
});

test("only the unexpired signed admin session is accepted", async () => {
  const secret = "local-test-session-secret-with-more-than-32-bytes";
  const nowSeconds = Math.floor(Date.now() / 1000);
  const tokenFor = (adminId, expiry, signingSecret = secret) => {
    const payload = Buffer.from(`${adminId}\n${expiry}`).toString("base64url");
    const signature = createHmac("sha256", signingSecret)
      .update(payload)
      .digest("base64url");
    return `${payload}.${signature}`;
  };
  const requestFor = (token) =>
    new Request("https://lapeace.amii.lol/api/dynamic-ssh", {
      headers: { Cookie: `amii_panel_session=${token}` },
    });
  const env = { PANEL_ADMIN_ID: "operator", PANEL_SESSION_SECRET: secret };

  assert.equal(
    await verifyAdminSession(requestFor(tokenFor("operator", nowSeconds + 60)), env),
    true,
  );
  assert.equal(
    await verifyAdminSession(requestFor(tokenFor("operator", nowSeconds - 1)), env),
    false,
  );
  assert.equal(
    await verifyAdminSession(
      requestFor(tokenFor("operator", nowSeconds + 60, "wrong secret")),
      env,
    ),
    false,
  );
  assert.equal(
    await verifyAdminSession(requestFor(tokenFor("other", nowSeconds + 60)), env),
    false,
  );
});

test("versioned user sessions are identified but never treated as admin sessions", async () => {
  const secret = "local-test-session-secret-with-more-than-32-bytes";
  const expiresAt = Math.floor(Date.now() / 1000) + 60;
  const payload = Buffer.from(
    `v2\nuser-account-id\nuser\nuser-account-id\n${expiresAt}`,
  ).toString("base64url");
  const signature = createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");
  const request = new Request("https://lapeace.amii.lol/api/dynamic-ssh", {
    headers: { Cookie: `amii_panel_session=${payload}.${signature}` },
  });
  const env = {
    PANEL_ADMIN_ID: "operator",
    PANEL_SESSION_SECRET: secret,
  };

  assert.deepEqual(await readSessionClaims(request, env), {
    subject: "user-account-id",
    role: "user",
    accountId: "user-account-id",
    expiresAt,
  });
  assert.equal(await verifyAdminSession(request, env), false);
});
