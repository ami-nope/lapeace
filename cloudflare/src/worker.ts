import { DurableObject } from "cloudflare:workers";
import {
  isExpired,
  isPublicIpv4,
  registerRecord,
  verifyAdminSession,
  type DynamicIpRecord,
  type SyncStatus,
} from "./core";

const MAX_SYNC_MESSAGE_LENGTH = 240;

export interface Env {
  DYNAMIC_IP_REGISTRY: DurableObjectNamespace<DynamicIpRegistry>;
  PANEL_ADMIN_ID: string;
  PANEL_SESSION_SECRET: string;
  DYNAMIC_SYNC_TOKEN: string;
  REGISTRATION_SOURCE: string;
}

interface RegistrySummary {
  records: DynamicIpRecord[];
  lastVpsSync: SyncStatus | null;
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

function bearerAuthorized(request: Request, token: string): boolean {
  if (token.length < 32) return false;
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

    if (pathname === "/api/dynamic-ssh" && request.method === "GET") {
      if (!(await verifyAdminSession(request, env))) {
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
      if (!(await verifyAdminSession(request, env))) {
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
  async fetch(request: Request): Promise<Response> {
    const { pathname, searchParams } = new URL(request.url);

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
