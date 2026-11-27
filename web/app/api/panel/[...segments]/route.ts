import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { isSameOrigin, SESSION_COOKIE, verifySessionToken } from "@/lib/session";

type RouteContext = { params: Promise<{ segments: string[] }> };
type Method = "GET" | "POST" | "DELETE";

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

async function proxy(
  request: Request,
  context: RouteContext,
  method: Method,
) {
  const cookieStore = await cookies();
  if (!verifySessionToken(cookieStore.get(SESSION_COOKIE)?.value)) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  if (method !== "GET") {
    if (!isSameOrigin(request)) {
      return NextResponse.json({ error: "Invalid request origin." }, { status: 403 });
    }
  }

  const { segments } = await context.params;
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
