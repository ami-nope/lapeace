import { DurableObject } from "cloudflare:workers";
import {
  normalizeUsername,
  publicAccount,
  validAccessWindow,
  validOptionalInteger,
  validOptionalRate,
  validScryptHash,
  validUsername,
  type AccountRecord,
} from "./accounts";
import {
  isExpired,
  isPublicIpv4,
  readSessionClaims,
  registerRecord,
  type DynamicIpRecord,
  type SyncStatus,
} from "./core";

const MAX_SYNC_MESSAGE_LENGTH = 240;
const ACCOUNT_API_PREFIX = "/api/account-store";
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_ATTEMPT_LIMIT = 5;
const AUDIT_RETENTION_MS = 3 * 24 * 60 * 60 * 1000;
const ADMIN_AUTH_VERSION_KEY = "session-version:admin";

export interface Env {
  DYNAMIC_IP_REGISTRY: DurableObjectNamespace<DynamicIpRegistry>;
  PANEL_ADMIN_ID?: string;
  PANEL_SESSION_SECRET?: string;
  DYNAMIC_SYNC_TOKEN?: string;
  ACCOUNT_STORE_TOKEN?: string;
  REGISTRATION_SOURCE?: string;
}

interface RegistrySummary {
  records: DynamicIpRecord[];
  lastVpsSync: SyncStatus | null;
}

interface LoginLimit {
  windowStartedAt: number;
  attempts: number;
}

interface AuditRecord {
  id: string;
  at: string;
  action: string;
  subject: string;
}

interface SessionIdentity {
  role: "admin" | "user";
  subject: string;
  accountId: string | null;
  authVersion: number;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function trustedClientIp(request: Request): string | null {
  const header = request.headers.get("cf-connecting-ip");
  if (!header || header.includes(",") || !isPublicIpv4(header)) return null;
  return header;
}

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

function bearerAuthorized(
  request: Request,
  token: string | undefined,
): boolean {
  if (!token || token.length < 32) return false;
  const authorization = request.headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ")) return false;
  const supplied = new TextEncoder().encode(authorization.slice(7));
  const expected = new TextEncoder().encode(token);
  if (supplied.length !== expected.length) return false;
  let difference = 0;
  for (let index = 0; index < supplied.length; index += 1) {
    difference |= supplied[index] ^ expected[index];
  }
  return difference === 0;
}

function validAccountPolicy(
  value: Record<string, unknown>,
): value is Record<string, unknown> & {
  dailyQuotaBytes: number | null;
  monthlyQuotaBytes: number | null;
  uploadLimitMbps: number | null;
  downloadLimitMbps: number | null;
  maxConcurrentConnections: number | null;
  accessWindow: null | { start: string; end: string; timeZone: string };
} {
  return (
    validOptionalInteger(value.dailyQuotaBytes, Number.MAX_SAFE_INTEGER) &&
    validOptionalInteger(value.monthlyQuotaBytes, Number.MAX_SAFE_INTEGER) &&
    validOptionalRate(value.uploadLimitMbps) &&
    validOptionalRate(value.downloadLimitMbps) &&
    validOptionalInteger(value.maxConcurrentConnections, 64) &&
    validAccessWindow(value.accessWindow)
  );
}

function validAccountCreate(
  value: unknown,
): value is {
  username: string;
  passwordHash: string;
  peerId: string;
  note: string;
  dailyQuotaBytes: number | null;
  monthlyQuotaBytes: number | null;
  uploadLimitMbps: number | null;
  downloadLimitMbps: number | null;
  maxConcurrentConnections: number | null;
  accessWindow: AccountRecord["accessWindow"];
} {
  return (
    typeof value === "object" &&
    value !== null &&
    "username" in value &&
    typeof value.username === "string" &&
    validUsername(value.username) &&
    "passwordHash" in value &&
    validScryptHash(value.passwordHash) &&
    "peerId" in value &&
    typeof value.peerId === "string" &&
    /^[a-f0-9]{64}$/.test(value.peerId) &&
    "note" in value &&
    typeof value.note === "string" &&
    value.note.length <= 240 &&
    validAccountPolicy(value as Record<string, unknown>)
  );
}

type AccountPatch = Partial<
  Pick<
    AccountRecord,
    | "status"
    | "note"
    | "dailyQuotaBytes"
    | "monthlyQuotaBytes"
    | "uploadLimitMbps"
    | "downloadLimitMbps"
    | "maxConcurrentConnections"
    | "accessWindow"
    | "passwordHash"
  >
>;

function validAccountPatch(value: unknown): value is AccountPatch {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const payload = value as Record<string, unknown>;
  const allowed = new Set([
    "status",
    "note",
    "dailyQuotaBytes",
    "monthlyQuotaBytes",
    "uploadLimitMbps",
    "downloadLimitMbps",
    "maxConcurrentConnections",
    "accessWindow",
    "passwordHash",
  ]);
  return (
    Object.keys(payload).length > 0 &&
    !Object.keys(payload).some((key) => !allowed.has(key)) &&
    (!("status" in payload) ||
      payload.status === "active" ||
      payload.status === "suspended") &&
    (!("note" in payload) ||
      (typeof payload.note === "string" && payload.note.length <= 240)) &&
    (!("dailyQuotaBytes" in payload) ||
      validOptionalInteger(payload.dailyQuotaBytes, Number.MAX_SAFE_INTEGER)) &&
    (!("monthlyQuotaBytes" in payload) ||
      validOptionalInteger(payload.monthlyQuotaBytes, Number.MAX_SAFE_INTEGER)) &&
    (!("uploadLimitMbps" in payload) || validOptionalRate(payload.uploadLimitMbps)) &&
    (!("downloadLimitMbps" in payload) ||
      validOptionalRate(payload.downloadLimitMbps)) &&
    (!("maxConcurrentConnections" in payload) ||
      validOptionalInteger(payload.maxConcurrentConnections, 64)) &&
    (!("accessWindow" in payload) || validAccessWindow(payload.accessWindow)) &&
    (!("passwordHash" in payload) || validScryptHash(payload.passwordHash))
  );
}

function validSessionIdentity(value: unknown): value is SessionIdentity {
  if (
    typeof value !== "object" ||
    value === null ||
    !("role" in value) ||
    (value.role !== "admin" && value.role !== "user") ||
    !("subject" in value) ||
    typeof value.subject !== "string" ||
    value.subject.length < 1 ||
    value.subject.length > 128 ||
    !("accountId" in value) ||
    !(value.accountId === null || typeof value.accountId === "string") ||
    !("authVersion" in value) ||
    !Number.isSafeInteger(value.authVersion) ||
    Number(value.authVersion) < 0
  ) {
    return false;
  }
  return value.role === "admin"
    ? value.accountId === null
    : value.accountId === value.subject;
}

function registryStub(env: Env): DurableObjectStub<DynamicIpRegistry> {
  const id = env.DYNAMIC_IP_REGISTRY.idFromName("lapeace-dynamic-ip-registry");
  return env.DYNAMIC_IP_REGISTRY.get(id);
}

async function registryRequest(
  env: Env,
  path: string,
  method = "GET",
  body?: unknown,
): Promise<Response> {
  return registryStub(env).fetch(
    new Request(`https://registry.internal${path}`, {
      method,
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
}

async function verifyLiveAdminSession(
  request: Request,
  env: Env,
): Promise<boolean> {
  const claims = await readSessionClaims(request, env);
  if (
    !claims ||
    claims.role !== "admin" ||
    claims.subject !== env.PANEL_ADMIN_ID
  ) {
    return false;
  }
  const response = await registryRequest(env, "/internal/session/validate", "POST", {
    role: claims.role,
    subject: claims.subject,
    accountId: null,
    authVersion: claims.authVersion,
  });
  if (!response.ok) return false;
  const result = await response.json<{ valid?: unknown }>().catch(() => null);
  return result?.valid === true;
}

async function readJson(request: Request): Promise<unknown> {
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (contentLength > 4096) throw new Error("Request body is too large.");
  const text = await request.text();
  if (text.length > 4096) throw new Error("Request body is too large.");
  return JSON.parse(text);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);

    if (pathname === "/health" && request.method === "GET") {
      const response = await registryRequest(env, "/internal/health");
      if (!response.ok) return jsonResponse({ status: "unavailable" }, 503);
      return jsonResponse({ status: "ok" });
    }

    if (pathname.startsWith(`${ACCOUNT_API_PREFIX}/`)) {
      if (!bearerAuthorized(request, env.ACCOUNT_STORE_TOKEN)) {
        return jsonResponse({ error: "Account-store authentication required." }, 401);
      }
      let payload: unknown;
      if (request.method === "POST" || request.method === "PATCH") {
        try {
          payload = await readJson(request);
        } catch {
          return jsonResponse({ error: "Invalid account-store request." }, 400);
        }
      }
      const internalPath =
        pathname.slice(ACCOUNT_API_PREFIX.length) + new URL(request.url).search;
      const response = await registryRequest(
        env,
        internalPath,
        request.method,
        payload,
      );
      return new Response(response.body, {
        status: response.status,
        headers: {
          "Content-Type": response.headers.get("Content-Type") ??
            "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }

    if (pathname === "/api/dynamic-ssh" && request.method === "GET") {
      if (!(await verifyLiveAdminSession(request, env))) {
        return jsonResponse({ error: "Authentication required." }, 401);
      }
      const currentIp = trustedClientIp(request);
      const response = await registryRequest(
        env,
        `/internal/summary?ip=${encodeURIComponent(currentIp ?? "")}`,
      );
      if (!response.ok) return jsonResponse({ error: "Registry unavailable." }, 503);
      const summary = (await response.json()) as RegistrySummary;
      const currentRecord = currentIp
        ? summary.records.find((record) => record.ip === currentIp)
        : undefined;
      const lastSuccessfulRegistration = summary.records
        .map((record) => record.lastUsedAt)
        .sort()
        .at(-1) ?? null;
      return jsonResponse({
        currentIp,
        ipError: currentIp ? null : "A public IPv4 address could not be established.",
        registrationStatus: currentRecord?.status ?? "not_registered",
        lastSuccessfulRegistration,
        lastVpsSync: summary.lastVpsSync,
        records: summary.records,
      });
    }

    if (pathname === "/api/dynamic-ssh/register" && request.method === "POST") {
      if (!(await verifyLiveAdminSession(request, env))) {
        return jsonResponse({ error: "Authentication required." }, 401);
      }
      if (!sameOrigin(request)) {
        return jsonResponse({ error: "Invalid request origin." }, 403);
      }
      const currentIp = trustedClientIp(request);
      if (!currentIp) {
        return jsonResponse(
          { error: "A globally routable public IPv4 address is required." },
          422,
        );
      }

      const response = await registryRequest(env, "/internal/register", "POST", {
        ip: currentIp,
        registeredAt: new Date().toISOString(),
        source: env.REGISTRATION_SOURCE || "cloudflare-edge",
      });
      if (!response.ok) return jsonResponse({ error: "Registry unavailable." }, 503);
      return jsonResponse(await response.json());
    }

    if (pathname === "/api/dynamic-ssh/sync/registry" && request.method === "GET") {
      if (!bearerAuthorized(request, env.DYNAMIC_SYNC_TOKEN)) {
        return jsonResponse({ error: "Service authentication required." }, 401);
      }
      const response = await registryRequest(env, "/internal/records");
      if (!response.ok) return jsonResponse({ error: "Registry unavailable." }, 503);
      return new Response(response.body, {
        status: 200,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }

    if (pathname === "/api/dynamic-ssh/sync/status" && request.method === "POST") {
      if (!bearerAuthorized(request, env.DYNAMIC_SYNC_TOKEN)) {
        return jsonResponse({ error: "Service authentication required." }, 401);
      }
      let payload: unknown;
      try {
        payload = await readJson(request);
      } catch {
        return jsonResponse({ error: "Invalid synchronization report." }, 400);
      }
      if (
        typeof payload !== "object" ||
        payload === null ||
        !("status" in payload) ||
        !["ok", "degraded", "error"].includes(String(payload.status)) ||
        !("added" in payload) ||
        !Number.isSafeInteger(payload.added) ||
        Number(payload.added) < 0 ||
        !("removed" in payload) ||
        !Number.isSafeInteger(payload.removed) ||
        Number(payload.removed) < 0 ||
        !("message" in payload) ||
        typeof payload.message !== "string" ||
        payload.message.length > MAX_SYNC_MESSAGE_LENGTH
      ) {
        return jsonResponse({ error: "Invalid synchronization report." }, 400);
      }
      const report: SyncStatus = {
        syncedAt: new Date().toISOString(),
        status: payload.status as SyncStatus["status"],
        added: Number(payload.added),
        removed: Number(payload.removed),
        message: payload.message,
      };
      const response = await registryRequest(
        env,
        "/internal/sync-status",
        "POST",
        report,
      );
      if (!response.ok) return jsonResponse({ error: "Registry unavailable." }, 503);
      return jsonResponse({ accepted: true, syncedAt: report.syncedAt });
    }

    return jsonResponse({ error: "Not found." }, 404);
  },
};

export class DynamicIpRegistry extends DurableObject<Env> {
  private async appendAudit(action: string, subject: string): Promise<void> {
    const now = Date.now();
    const record: AuditRecord = {
      id: crypto.randomUUID(),
      at: new Date(now).toISOString(),
      action,
      subject,
    };
    await this.ctx.storage.transaction(async (transaction) => {
      const entries = await transaction.list<AuditRecord>({ prefix: "audit:" });
      for (const [key, existing] of entries) {
        if (Date.parse(existing.at) < now - AUDIT_RETENTION_MS) {
          await transaction.delete(key);
        }
      }
      await transaction.put(`audit:${String(now).padStart(13, "0")}:${record.id}`, record);
    });
  }

  private async getAccountById(id: string): Promise<AccountRecord | undefined> {
    const stored = await this.ctx.storage.get<AccountRecord>(`account:${id}`);
    if (!stored) return undefined;
    return {
      ...stored,
      authVersion: Number.isSafeInteger(stored.authVersion)
        ? stored.authVersion
        : 0,
    };
  }

  async fetch(request: Request): Promise<Response> {
    const { pathname, searchParams } = new URL(request.url);

    if (pathname === "/internal/health" && request.method === "GET") {
      return jsonResponse({ status: "ok" });
    }

    if (
      pathname === "/internal/session/admin-version" &&
      request.method === "GET"
    ) {
      const authVersion =
        (await this.ctx.storage.get<number>(ADMIN_AUTH_VERSION_KEY)) ?? 0;
      return jsonResponse({ authVersion });
    }

    if (
      pathname === "/internal/session/validate" &&
      request.method === "POST"
    ) {
      const payload = await request.json<unknown>().catch(() => null);
      if (!validSessionIdentity(payload)) {
        return jsonResponse({ error: "Invalid session validation request." }, 400);
      }
      if (payload.role === "admin") {
        const authVersion =
          (await this.ctx.storage.get<number>(ADMIN_AUTH_VERSION_KEY)) ?? 0;
        return jsonResponse({
          valid:
            payload.subject === this.env.PANEL_ADMIN_ID &&
            payload.authVersion === authVersion,
        });
      }
      if (!payload.accountId) {
        return jsonResponse({ error: "Invalid user session identity." }, 400);
      }
      const account = await this.getAccountById(payload.accountId);
      return jsonResponse({
        valid:
          account?.status === "active" &&
          account.authVersion === payload.authVersion,
      });
    }

    if (
      pathname === "/internal/session/logout" &&
      request.method === "POST"
    ) {
      const payload = await request.json<unknown>().catch(() => null);
      if (!validSessionIdentity(payload)) {
        return jsonResponse({ error: "Invalid session revocation request." }, 400);
      }
      if (payload.role === "admin") {
        if (payload.subject !== this.env.PANEL_ADMIN_ID) {
          return jsonResponse({ error: "Session revocation rejected." }, 403);
        }
        await this.ctx.storage.transaction(async (transaction) => {
          const current =
            (await transaction.get<number>(ADMIN_AUTH_VERSION_KEY)) ?? 0;
          if (current === payload.authVersion) {
            await transaction.put(ADMIN_AUTH_VERSION_KEY, current + 1);
          }
        });
      } else {
        await this.ctx.storage.transaction(async (transaction) => {
          const key = `account:${payload.accountId}`;
          const account = await transaction.get<AccountRecord>(key);
          if (!account) return;
          const current = Number.isSafeInteger(account.authVersion)
            ? account.authVersion
            : 0;
          if (current === payload.authVersion) {
            await transaction.put(key, {
              ...account,
              authVersion: current + 1,
              updatedAt: new Date().toISOString(),
            });
          }
        });
      }
      return jsonResponse({ revoked: true });
    }

    if (pathname === "/internal/login/check" && request.method === "POST") {
      const payload = await request.json<Record<string, unknown>>().catch(() => null);
      if (
        typeof payload?.identifier !== "string" ||
        payload.identifier.length < 1 ||
        payload.identifier.length > 128
      ) {
        return jsonResponse({ error: "Invalid login identifier." }, 400);
      }
      const identifier = normalizeUsername(payload.identifier);
      const key = `login-limit:${encodeURIComponent(identifier)}`;
      const now = Date.now();
      const allowed = await this.ctx.storage.transaction(async (transaction) => {
        const existing = await transaction.get<LoginLimit>(key);
        const limit =
          existing && now - existing.windowStartedAt < LOGIN_WINDOW_MS
            ? existing
            : { windowStartedAt: now, attempts: 0 };
        if (limit.attempts >= LOGIN_ATTEMPT_LIMIT) return false;
        limit.attempts += 1;
        await transaction.put(key, limit);
        return true;
      });
      return jsonResponse({ allowed }, allowed ? 200 : 429);
    }

    if (pathname === "/internal/login/finish" && request.method === "POST") {
      const payload = await request.json<Record<string, unknown>>().catch(() => null);
      if (
        typeof payload?.identifier !== "string" ||
        payload.identifier.length < 1 ||
        payload.identifier.length > 128 ||
        typeof payload.success !== "boolean"
      ) {
        return jsonResponse({ error: "Invalid login result." }, 400);
      }
      const identifier = normalizeUsername(payload.identifier);
      const key = `login-limit:${encodeURIComponent(identifier)}`;
      if (payload.success) {
        await this.ctx.storage.delete(key);
        await this.appendAudit("login_success", identifier);
      } else {
        await this.appendAudit("login_failed", identifier);
      }
      return jsonResponse({ accepted: true });
    }

    if (pathname === "/internal/login/lookup" && request.method === "POST") {
      const payload = await request.json<Record<string, unknown>>().catch(() => null);
      if (
        typeof payload?.username !== "string" ||
        !validUsername(payload.username)
      ) {
        return jsonResponse({ error: "Invalid account lookup." }, 400);
      }
      const id = await this.ctx.storage.get<string>(
        `account-name:${normalizeUsername(payload.username)}`,
      );
      const account = id ? await this.getAccountById(id) : undefined;
      return jsonResponse({
        account: account
          ? {
              id: account.id,
              username: account.username,
              status: account.status,
              passwordHash: account.passwordHash,
              authVersion: account.authVersion ?? 0,
            }
          : null,
      });
    }

    if (pathname === "/internal/profile" && request.method === "GET") {
      const id = searchParams.get("id") ?? "";
      const account = /^[0-9a-f-]{36}$/i.test(id)
        ? await this.getAccountById(id)
        : undefined;
      if (!account) return jsonResponse({ error: "Account not found." }, 404);
      return jsonResponse({ account: publicAccount(account) });
    }

    if (pathname === "/internal/accounts" && request.method === "GET") {
      const entries = await this.ctx.storage.list<AccountRecord>({ prefix: "account:" });
      const accounts = [...entries.values()]
        .map(publicAccount)
        .sort((left, right) => left.username.localeCompare(right.username));
      return jsonResponse({ accounts });
    }

    if (pathname === "/internal/accounts" && request.method === "POST") {
      const payload = await request.json<unknown>().catch(() => null);
      if (!this.env.PANEL_ADMIN_ID) {
        return jsonResponse({ error: "Account service is not configured." }, 503);
      }
      if (
        !validAccountCreate(payload) ||
        normalizeUsername(payload.username) ===
          normalizeUsername(this.env.PANEL_ADMIN_ID)
      ) {
        return jsonResponse({ error: "Invalid account details." }, 400);
      }
      const record: AccountRecord = {
        id: crypto.randomUUID(),
        username: payload.username.trim(),
        normalizedUsername: normalizeUsername(payload.username),
        passwordHash: payload.passwordHash,
        authVersion: 0,
        peerId: payload.peerId,
        note: payload.note.trim(),
        status: "active",
        dailyQuotaBytes: payload.dailyQuotaBytes,
        monthlyQuotaBytes: payload.monthlyQuotaBytes,
        uploadLimitMbps: payload.uploadLimitMbps,
        downloadLimitMbps: payload.downloadLimitMbps,
        maxConcurrentConnections: payload.maxConcurrentConnections,
        accessWindow: payload.accessWindow,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      const created = await this.ctx.storage.transaction(async (transaction) => {
        const nameKey = `account-name:${record.normalizedUsername}`;
        if (await transaction.get(nameKey)) return false;
        const existing = await transaction.list<AccountRecord>({ prefix: "account:" });
        if ([...existing.values()].some((account) => account.peerId === record.peerId)) {
          return false;
        }
        await transaction.put(`account:${record.id}`, record);
        await transaction.put(nameKey, record.id);
        return true;
      });
      if (!created) {
        return jsonResponse(
          { error: "Account name or peer is already assigned." },
          409,
        );
      }
      await this.appendAudit("account_created", record.username);
      return jsonResponse({ account: publicAccount(record) }, 201);
    }

    if (pathname.startsWith("/internal/accounts/") && request.method === "PATCH") {
      const id = pathname.slice("/internal/accounts/".length);
      if (!/^[0-9a-f-]{36}$/i.test(id)) {
        return jsonResponse({ error: "Account not found." }, 404);
      }
      const payload = await request.json<unknown>().catch(() => null);
      if (!validAccountPatch(payload)) {
        return jsonResponse({ error: "Invalid account update." }, 400);
      }
      const updated = await this.ctx.storage.transaction(async (transaction) => {
        const key = `account:${id}`;
        const account = await transaction.get<AccountRecord>(key);
        if (!account) return undefined;
        const authVersion = Number.isSafeInteger(account.authVersion)
          ? account.authVersion
          : 0;
        const revokeExistingSessions =
          payload.passwordHash !== undefined ||
          (payload.status !== undefined && payload.status !== account.status);
        const next: AccountRecord = {
          ...account,
          ...payload,
          authVersion: authVersion + Number(revokeExistingSessions),
          note: typeof payload.note === "string" ? payload.note.trim() : account.note,
          updatedAt: new Date().toISOString(),
        };
        await transaction.put(key, next);
        return next;
      });
      if (!updated) return jsonResponse({ error: "Account not found." }, 404);
      await this.appendAudit("account_updated", updated.username);
      return jsonResponse({ account: publicAccount(updated) });
    }

    if (pathname.startsWith("/internal/accounts/") && request.method === "DELETE") {
      const id = pathname.slice("/internal/accounts/".length);
      if (!/^[0-9a-f-]{36}$/i.test(id)) {
        return jsonResponse({ error: "Account not found." }, 404);
      }
      const deleted = await this.ctx.storage.transaction(async (transaction) => {
        const key = `account:${id}`;
        const account = await transaction.get<AccountRecord>(key);
        if (!account) return undefined;
        await transaction.delete(key);
        await transaction.delete(`account-name:${account.normalizedUsername}`);
        return account;
      });
      if (!deleted) return jsonResponse({ error: "Account not found." }, 404);
      await this.appendAudit("account_deleted", deleted.username);
      return jsonResponse({ deleted: true });
    }

    if (pathname === "/internal/audit" && request.method === "GET") {
      const now = Date.now();
      const { events, failedLoginCount } =
        await this.ctx.storage.transaction(async (transaction) => {
        const entries = await transaction.list<AuditRecord>({ prefix: "audit:" });
        const retained: AuditRecord[] = [];
        for (const [key, record] of entries) {
          if (Date.parse(record.at) < now - AUDIT_RETENTION_MS) {
            await transaction.delete(key);
          } else {
            retained.push(record);
          }
        }
        retained.sort((left, right) => right.at.localeCompare(left.at));
        return {
          events: retained.slice(0, 100),
          failedLoginCount: retained.filter((event) => event.action === "login_failed").length,
        };
      });
      return jsonResponse({
        events,
        retentionDays: 3,
        failedLoginCount,
      });
    }

    if (pathname === "/internal/summary" && request.method === "GET") {
      const now = Date.now();
      const summary = await this.ctx.storage.transaction(async (transaction) => {
        const entries = await transaction.list<DynamicIpRecord>({ prefix: "ip:" });
        const records: DynamicIpRecord[] = [];
        for (const [key, record] of entries) {
          const status: DynamicIpRecord["status"] = isExpired(record.lastUsedAt, now)
            ? "expired"
            : "active";
          const updated = { ...record, status };
          if (record.status !== status) await transaction.put(key, updated);
          records.push(updated);
        }
        const lastVpsSync =
          (await transaction.get<SyncStatus>("sync-status")) ?? null;
        return {
          records: records.sort((left, right) => left.ip.localeCompare(right.ip)),
          lastVpsSync,
        };
      });
      return jsonResponse(summary);
    }

    if (pathname === "/internal/records" && request.method === "GET") {
      const now = Date.now();
      const records = await this.ctx.storage.transaction(async (transaction) => {
        const entries = await transaction.list<DynamicIpRecord>({ prefix: "ip:" });
        const result: DynamicIpRecord[] = [];
        for (const [key, record] of entries) {
          const status: DynamicIpRecord["status"] = isExpired(record.lastUsedAt, now)
            ? "expired"
            : "active";
          const updated = { ...record, status };
          if (record.status !== status) await transaction.put(key, updated);
          result.push(updated);
        }
        return result.sort((left, right) => left.ip.localeCompare(right.ip));
      });
      return jsonResponse({
        version: 1,
        generatedAt: new Date(now).toISOString(),
        records,
      });
    }

    if (pathname === "/internal/register" && request.method === "POST") {
      let payload: unknown;
      try {
        payload = await request.json();
      } catch {
        return jsonResponse({ error: "Invalid registration." }, 400);
      }
      if (
        typeof payload !== "object" ||
        payload === null ||
        !("ip" in payload) ||
        typeof payload.ip !== "string" ||
        !isPublicIpv4(payload.ip) ||
        !("registeredAt" in payload) ||
        typeof payload.registeredAt !== "string" ||
        !Number.isFinite(Date.parse(payload.registeredAt)) ||
        !("source" in payload) ||
        typeof payload.source !== "string"
      ) {
        return jsonResponse({ error: "Invalid registration." }, 400);
      }
      const registration = payload as {
        ip: string;
        registeredAt: string;
        source: string;
      };
      const record = await this.ctx.storage.transaction(async (transaction) => {
        const key = `ip:${registration.ip}`;
        const existing = await transaction.get<DynamicIpRecord>(key);
        const updated = registerRecord(
          existing,
          registration.ip,
          registration.registeredAt,
          registration.source,
        );
        await transaction.put(key, updated);
        return updated;
      });
      return jsonResponse({ record });
    }

    if (pathname === "/internal/sync-status" && request.method === "POST") {
      let payload: unknown;
      try {
        payload = await request.json();
      } catch {
        return jsonResponse({ error: "Invalid synchronization report." }, 400);
      }
      if (
        typeof payload !== "object" ||
        payload === null ||
        !("syncedAt" in payload) ||
        typeof payload.syncedAt !== "string" ||
        !Number.isFinite(Date.parse(payload.syncedAt))
      ) {
        return jsonResponse({ error: "Invalid synchronization report." }, 400);
      }
      await this.ctx.storage.put("sync-status", payload);
      return jsonResponse({ accepted: true });
    }

    return jsonResponse({ error: "Not found." }, 404);
  }
}
