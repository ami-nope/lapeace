import { createHmac, scryptSync, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE = "amii_panel_session";
const SESSION_SECONDS = 12 * 60 * 60;

export function isSameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (!origin || !host) return false;

  const forwardedProtocol = request.headers
    .get("x-forwarded-proto")
    ?.split(",")[0]
    .trim();
  const protocol = forwardedProtocol || new URL(request.url).protocol.slice(0, -1);
  if (protocol !== "http" && protocol !== "https") return false;

  try {
    return new URL(origin).origin === new URL(`${protocol}://${host}`).origin;
  } catch {
    return false;
  }
}

function sessionSecret(): string | null {
  const secret = process.env.PANEL_SESSION_SECRET;
  return secret && Buffer.byteLength(secret) >= 32 ? secret : null;
}

function sign(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return (
    leftBuffer.length === rightBuffer.length &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}

export function verifyAdminCredentials(adminId: string, password: string): boolean {
  const expectedId = process.env.PANEL_ADMIN_ID;
  const storedHash = process.env.PANEL_ADMIN_PASSWORD_HASH;
  if (!expectedId || !storedHash || !safeEqual(adminId, expectedId)) return false;

  const parts = storedHash.split(":");
  if (
    parts.length !== 3 ||
    parts[0] !== "scrypt" ||
    !/^[a-f0-9]{32}$/i.test(parts[1]) ||
    !/^[a-f0-9]{128}$/i.test(parts[2])
  ) {
    return false;
  }

  const actual = scryptSync(password, Buffer.from(parts[1], "hex"), 64).toString(
    "hex",
  );
  return safeEqual(actual, parts[2].toLowerCase());
}

export function createSessionToken(): string | null {
  const secret = sessionSecret();
  const adminId = process.env.PANEL_ADMIN_ID;
  if (!secret || !adminId) return null;

  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const payload = Buffer.from(`${adminId}\n${expiresAt}`).toString("base64url");
  return `${payload}.${sign(payload, secret)}`;
}

export function verifySessionToken(token: string | undefined): boolean {
  const secret = sessionSecret();
  if (!token || !secret) return false;

  const [payload, signature, extra] = token.split(".");
  if (!payload || !signature || extra !== undefined) return false;
  if (!safeEqual(signature, sign(payload, secret))) return false;

  let decoded: string;
  try {
    decoded = Buffer.from(payload, "base64url").toString("utf8");
  } catch {
    return false;
  }
  const [adminId, expiresAtText, remainder] = decoded.split("\n");
  const expiresAt = Number(expiresAtText);
  return (
    remainder === undefined &&
    adminId === process.env.PANEL_ADMIN_ID &&
    Number.isSafeInteger(expiresAt) &&
    expiresAt > Math.floor(Date.now() / 1000)
  );
}

export { SESSION_SECONDS };
