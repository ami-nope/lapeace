import { NextResponse } from "next/server";
import { AgentUsageError, baselineForPeer, getAgentUsageSnapshot } from "@/lib/agent-usage";
import { accountStoreFetch } from "@/lib/account-store";
import { getRequestSession } from "@/lib/api-auth";
import { isSameOrigin } from "@/lib/session";
import {
  calculateAccountUsage,
  isUsageAssignment,
  UsageTelemetryUnavailableError,
} from "@/lib/usage-accounting";

type RouteContext = { params: Promise<{ segments: string[] }> };
type Method = "GET" | "POST" | "DELETE";

function isAllowed(method: Method, segments: string[]): boolean {
  const path = segments.join("/");
  if (method === "GET" && (path === "snapshot" || path === "events")) return true;
  if (method === "GET" && path === "clients") return true;
  if (method === "POST" && path === "clients") return true;
  if (
    method === "POST" &&
    /^clients\/[a-f0-9]{64}\/(pause|resume|regenerate)$/.test(path)
  ) {
    return true;
  }
  if (method === "DELETE" && /^clients\/[a-f0-9]{64}$/.test(path)) return true;
  if (
    method === "GET" &&
    /^clients\/[a-f0-9]{64}\/config(?:\/qr)?$/.test(path)
  ) {
    return true;
  }
  return false;
}

function peerDestructiveOperation(method: Method, segments: string[]): string | null {
  const peerId = segments[1];
  if (
    typeof peerId === "string" &&
    /^[a-f0-9]{64}$/.test(peerId) &&
    ((method === "DELETE" && segments.length === 2 && segments[0] === "clients") ||
      (method === "POST" &&
        segments.length === 3 &&
        segments[0] === "clients" &&
        segments[2] === "regenerate"))
  ) {
    return peerId;
  }
  return null;
}

async function ensurePeerUnassigned(peerId: string): Promise<Response | null> {
  let response: Response;
  try {
    response = await accountStoreFetch("internal/accounts");
  } catch {
    return NextResponse.json(
      { error: "Cannot verify peer assignments; account store is unavailable." },
      { status: 503 },
    );
  }
  if (!response.ok) {
    return NextResponse.json(
      { error: "Cannot verify peer assignments." },
      { status: 503 },
    );
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return NextResponse.json(
      { error: "Account store returned invalid assignment data." },
      { status: 503 },
    );
  }
  if (
    typeof payload !== "object" ||
    payload === null ||
    !("accounts" in payload) ||
    !Array.isArray(payload.accounts) ||
    !payload.accounts.every(
      (account) =>
        typeof account === "object" &&
        account !== null &&
        "peerId" in account &&
        typeof account.peerId === "string" &&
        /^[a-f0-9]{64}$/.test(account.peerId),
    )
  ) {
    return NextResponse.json(
      { error: "Account store returned invalid assignment data." },
      { status: 503 },
    );
  }
  if (payload.accounts.some((account) => account.peerId === peerId)) {
    return NextResponse.json(
      { error: "Reassign this peer from every account before revoking or regenerating it." },
      { status: 409 },
    );
  }
  return null;
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
      monthlyQuotaBytes: number | null;
      usageAssignments: unknown;
    };
  };
  if (accountResult.account.status !== "active") {
    return NextResponse.json({ error: "Account is unavailable." }, { status: 401 });
  }

  let snapshot;
  try {
    snapshot = await getAgentUsageSnapshot();
  } catch (error) {
    if (error instanceof AgentUsageError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.status, headers: { "Cache-Control": "no-store" } },
      );
    }
    throw error;
  }

  let assignments: unknown = accountResult.account.usageAssignments;
  if (!Array.isArray(assignments) || !assignments.every(isUsageAssignment)) {
    return NextResponse.json(
      { error: "Account assignment data is invalid." },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
  if (assignments.length === 0) {
    let baseline;
    try {
      baseline = baselineForPeer(snapshot, accountResult.account.peerId);
      const migration = await accountStoreFetch(
        "internal/profile/assignment-baseline",
        "POST",
        { id: accountId, baseline },
      );
      if (!migration.ok) {
        return NextResponse.json(
          { error: "Could not initialize account usage tracking." },
          { status: 503, headers: { "Cache-Control": "no-store" } },
        );
      }
      const migrated = (await migration.json()) as { usageAssignments?: unknown };
      assignments = migrated.usageAssignments;
    } catch (error) {
      if (error instanceof AgentUsageError) {
        return NextResponse.json(
          { error: error.message },
          { status: error.status, headers: { "Cache-Control": "no-store" } },
        );
      }
      return NextResponse.json(
        { error: "Could not initialize account usage tracking." },
        { status: 503, headers: { "Cache-Control": "no-store" } },
      );
    }
    if (!Array.isArray(assignments) || !assignments.every(isUsageAssignment)) {
      return NextResponse.json(
        { error: "Account assignment data is invalid." },
        { status: 503, headers: { "Cache-Control": "no-store" } },
      );
    }
  }

  try {
    const usage = calculateAccountUsage({
      assignments,
      snapshot,
      dailyQuotaBytes: accountResult.account.dailyQuotaBytes,
      monthlyQuotaBytes: accountResult.account.monthlyQuotaBytes,
    });
    return NextResponse.json(usage, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error) {
    if (error instanceof UsageTelemetryUnavailableError) {
      return NextResponse.json(
        { error: error.message },
        { status: 503, headers: { "Cache-Control": "no-store" } },
      );
    }
    throw error;
  }
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
  const protectedPeerId = peerDestructiveOperation(method, segments);
  if (protectedPeerId) {
    const assignmentError = await ensurePeerUnassigned(protectedPeerId);
    if (assignmentError) return assignmentError;
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
  const responseHeaders = new Headers({
    "Content-Type": contentType,
    "Cache-Control": "no-store",
  });
  const disposition = upstream.headers.get("content-disposition");
  if (disposition) {
    responseHeaders.set("Content-Disposition", disposition);
  }
  return new Response(await upstream.arrayBuffer(), {
    status: upstream.status,
    headers: responseHeaders,
  });
}

export const GET = (request: Request, context: RouteContext) =>
  proxy(request, context, "GET");
export const POST = (request: Request, context: RouteContext) =>
  proxy(request, context, "POST");
export const DELETE = (request: Request, context: RouteContext) =>
  proxy(request, context, "DELETE");
