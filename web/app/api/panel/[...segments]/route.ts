import { NextResponse } from "next/server";
import { accountStoreFetch } from "@/lib/account-store";
import { getRequestSession } from "@/lib/api-auth";
import { isSameOrigin } from "@/lib/session";

type RouteContext = { params: Promise<{ segments: string[] }> };
type Method = "GET" | "POST" | "DELETE";

type UserSnapshot = {
  sampledAt: string;
  peers: Array<{
    id: string;
    todayBytes: number;
    rxBps: number;
    txBps: number;
  }>;
};

function isUserSnapshot(value: unknown): value is UserSnapshot {
  if (
    typeof value !== "object" ||
    value === null ||
    !("sampledAt" in value) ||
    typeof value.sampledAt !== "string" ||
    !("peers" in value) ||
    !Array.isArray(value.peers)
  ) {
    return false;
  }
  return value.peers.every(
    (peer) =>
      typeof peer === "object" &&
      peer !== null &&
      "id" in peer &&
      typeof peer.id === "string" &&
      "todayBytes" in peer &&
      typeof peer.todayBytes === "number" &&
      Number.isFinite(peer.todayBytes) &&
      peer.todayBytes >= 0 &&
      "rxBps" in peer &&
      typeof peer.rxBps === "number" &&
      Number.isFinite(peer.rxBps) &&
      peer.rxBps >= 0 &&
      "txBps" in peer &&
      typeof peer.txBps === "number" &&
      Number.isFinite(peer.txBps) &&
      peer.txBps >= 0,
  );
}

function isAllowed(method: Method, segments: string[]): boolean {
  const path = segments.join("/");
  if (method === "GET" && (path === "snapshot" || path === "events")) return true;
  if (method === "POST" && path === "clients") return true;
  if (
    method === "POST" &&
    /^clients\/[a-f0-9]{64}\/(pause|resume)$/.test(path)
  ) {
    return true;
  }
  if (method === "DELETE" && /^clients\/[a-f0-9]{64}$/.test(path)) return true;
  if (
    method === "GET" &&
    /^clients\/[a-f0-9]{64}\/config$/.test(path)
  ) {
    return true;
  }
  return false;
}

async function userSummary(accountId: string): Promise<Response> {
  let accountResponse: Response;
  try {
    accountResponse = await accountStoreFetch(
      `internal/profile?id=${encodeURIComponent(accountId)}`,
    );
  } catch {
    return NextResponse.json({ error: "Account store is unavailable." }, { status: 503 });
  }
  if (!accountResponse.ok) {
    return NextResponse.json(
      { error: "Account is unavailable." },
      { status: accountResponse.status === 404 ? 401 : accountResponse.status },
    );
  }
  const accountResult = (await accountResponse.json()) as {
    account: {
      status: "active" | "suspended";
      peerId: string;
      dailyQuotaBytes: number | null;
    };
  };
  if (accountResult.account.status !== "active") {
    return NextResponse.json({ error: "Account is unavailable." }, { status: 401 });
  }

  const baseUrl = process.env.AGENT_BASE_URL;
  const apiToken = process.env.AGENT_API_TOKEN;
  if (!baseUrl || !apiToken) {
    return NextResponse.json(
      { error: "The VPS agent is not configured." },
      { status: 503 },
    );
  }
  let target: URL;
  try {
    target = new URL("/api/v1/snapshot", baseUrl);
  } catch {
    return NextResponse.json(
      { error: "The VPS agent address is invalid." },
      { status: 503 },
    );
  }
  if (
    target.protocol !== "https:" &&
    target.hostname !== "localhost" &&
    target.hostname !== "127.0.0.1"
  ) {
    return NextResponse.json(
      { error: "The VPS agent must use HTTPS." },
      { status: 503 },
    );
  }

  let upstream: Response;
  try {
    upstream = await fetch(target, {
      headers: { Authorization: `Bearer ${apiToken}` },
      cache: "no-store",
      signal: AbortSignal.timeout(7_000),
    });
  } catch (error) {
    if (error instanceof TypeError || error instanceof DOMException) {
      return NextResponse.json(
        { error: "The VPS agent could not be reached." },
        { status: 502 },
      );
    }
    throw error;
  }
  if (!upstream.ok) {
    return NextResponse.json(
      { error: "The VPS agent returned an error." },
      { status: upstream.status },
    );
  }

  let snapshot: UserSnapshot;
  try {
    const payload: unknown = await upstream.json();
    if (!isUserSnapshot(payload)) {
      return NextResponse.json(
        { error: "The VPS agent returned invalid telemetry." },
        { status: 502, headers: { "Cache-Control": "no-store" } },
      );
    }
    snapshot = payload;
  } catch {
    return NextResponse.json(
      { error: "The VPS agent returned invalid telemetry." },
      { status: 502, headers: { "Cache-Control": "no-store" } },
    );
  }
  const peer = snapshot.peers.find(
    (record) => record.id === accountResult.account.peerId,
  );
  return NextResponse.json(
    {
      sampledAt: snapshot.sampledAt,
      todayBytes: peer?.todayBytes ?? 0,
      uploadBps: peer?.rxBps ?? 0,
      downloadBps: peer?.txBps ?? 0,
      dailyQuotaBytes: accountResult.account.dailyQuotaBytes,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}

async function proxy(
  request: Request,
  context: RouteContext,
  method: Method,
) {
  const session = await getRequestSession();
  if (!session) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  if (method !== "GET") {
    if (!isSameOrigin(request)) {
      return NextResponse.json({ error: "Invalid request origin." }, { status: 403 });
    }
  }

  const { segments } = await context.params;
  if (session.role === "user") {
    if (method === "GET" && segments.join("/") === "summary" && session.accountId) {
      return userSummary(session.accountId);
    }
    return NextResponse.json({ error: "Unknown panel operation." }, { status: 404 });
  }
  if (!isAllowed(method, segments)) {
    return NextResponse.json({ error: "Unknown panel operation." }, { status: 404 });
  }

  const baseUrl = process.env.AGENT_BASE_URL;
  const apiToken = process.env.AGENT_API_TOKEN;
  if (!baseUrl || !apiToken) {
    return NextResponse.json(
      { error: "The VPS agent is not configured." },
      { status: 503 },
    );
  }

  let target: URL;
  try {
    target = new URL(
      `/api/v1/${segments.map(encodeURIComponent).join("/")}`,
      baseUrl,
    );
  } catch {
    return NextResponse.json(
      { error: "The VPS agent address is invalid." },
      { status: 503 },
    );
  }

  if (
    target.protocol !== "https:" &&
    target.hostname !== "localhost" &&
    target.hostname !== "127.0.0.1"
  ) {
    return NextResponse.json(
      { error: "The VPS agent must use HTTPS." },
      { status: 503 },
    );
  }

  const headers = new Headers({ Authorization: `Bearer ${apiToken}` });
  let body: string | undefined;
  if (method !== "GET") {
    headers.set("Content-Type", "application/json");
    body = await request.text();
    if (body.length > 16_384) {
      return NextResponse.json({ error: "Request body is too large." }, { status: 413 });
    }
  }

  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method,
      headers,
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(7_000),
    });
  } catch (error) {
    if (error instanceof TypeError || error instanceof DOMException) {
      return NextResponse.json(
        { error: "The VPS agent could not be reached." },
        { status: 502 },
      );
    }
    throw error;
  }

  const contentType = upstream.headers.get("content-type") ?? "application/json";
  return new Response(await upstream.arrayBuffer(), {
    status: upstream.status,
    headers: {
      "Content-Type": contentType,
      "Cache-Control": "no-store",
    },
  });
}

export const GET = (request: Request, context: RouteContext) =>
  proxy(request, context, "GET");
export const POST = (request: Request, context: RouteContext) =>
  proxy(request, context, "POST");
export const DELETE = (request: Request, context: RouteContext) =>
  proxy(request, context, "DELETE");
