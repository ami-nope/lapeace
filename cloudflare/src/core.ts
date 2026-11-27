export const SESSION_COOKIE = "amii_panel_session";
export const REGISTRATION_TTL_MS = 15 * 24 * 60 * 60 * 1000;

export interface DynamicIpRecord {
  ip: string;
  firstRegisteredAt: string;
  lastUsedAt: string;
  registrationSource: string;
  status: "active" | "expired";
}

export interface SyncStatus {
  syncedAt: string;
  status: "ok" | "degraded" | "error";
  added: number;
  removed: number;
  message: string;
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  if (leftBytes.length !== rightBytes.length) return false;
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= leftBytes[index] ^ rightBytes[index];
  }
  return difference === 0;
}

function decodeBase64Url(value: string): Uint8Array | null {
  try {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function signSessionPayload(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload),
  );
  return encodeBase64Url(signature);
}

function cookieValue(request: Request, name: string): string | null {
  const cookieHeader = request.headers.get("cookie") ?? "";
  for (const item of cookieHeader.split(";")) {
    const separator = item.indexOf("=");
    if (separator < 0 || item.slice(0, separator).trim() !== name) continue;
    return item.slice(separator + 1).trim();
  }
  return null;
}

export async function verifyAdminSession(
  request: Request,
  env: { PANEL_ADMIN_ID: string; PANEL_SESSION_SECRET: string },
): Promise<boolean> {
  if (
    !env.PANEL_ADMIN_ID ||
    new TextEncoder().encode(env.PANEL_SESSION_SECRET).length < 32
  ) {
    return false;
  }
  const token = cookieValue(request, SESSION_COOKIE);
  if (!token || token.length > 2048) return false;

  const separator = token.indexOf(".");
  if (separator <= 0 || separator !== token.lastIndexOf(".")) return false;
  const payload = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  const expected = await signSessionPayload(payload, env.PANEL_SESSION_SECRET);
  if (!constantTimeEqual(signature, expected)) return false;

  const bytes = decodeBase64Url(payload);
  if (!bytes) return false;
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return false;
  }
  const [adminId, expiresAtText, remainder] = decoded.split("\n");
  const expiresAt = Number(expiresAtText);
  return (
    remainder === undefined &&
    adminId === env.PANEL_ADMIN_ID &&
    Number.isSafeInteger(expiresAt) &&
    expiresAt > Math.floor(Date.now() / 1000)
  );
}

export function isPublicIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9]\d{0,2})$/.test(part))) {
    return false;
  }
  const octets = parts.map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255)) return false;

  const number =
    octets[0] * 0x1000000 +
    octets[1] * 0x10000 +
    octets[2] * 0x100 +
    octets[3];
  const inRange = (network: number, prefix: number) => {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return ((number >>> 0) & mask) === ((network >>> 0) & mask);
  };
  const blocked = [
    [0x00000000, 8],
    [0x0a000000, 8],
    [0x64400000, 10],
    [0x7f000000, 8],
    [0xa9fe0000, 16],
    [0xac100000, 12],
    [0xc0000000, 24],
    [0xc0000200, 24],
    [0xc0586300, 24],
    [0xc0a80000, 16],
    [0xc6120000, 15],
    [0xc6336400, 24],
    [0xcb007100, 24],
  ] as const;
  return (
    octets[0] < 224 &&
    octets[0] !== 255 &&
    !blocked.some(([network, prefix]) => inRange(network, prefix))
  );
}

export function isExpired(lastUsedAt: string, now: number): boolean {
  const lastUsed = Date.parse(lastUsedAt);
  return Number.isFinite(lastUsed) && now - lastUsed > REGISTRATION_TTL_MS;
}

export function registerRecord(
  existing: DynamicIpRecord | undefined,
  ip: string,
  registeredAt: string,
  source: string,
): DynamicIpRecord {
  return {
    ip,
    firstRegisteredAt: existing?.firstRegisteredAt ?? registeredAt,
    lastUsedAt: registeredAt,
    registrationSource: source,
    status: "active",
  };
}
