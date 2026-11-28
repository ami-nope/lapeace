import { NextResponse } from "next/server";
import { AgentUsageError, baselineForPeer, getAgentUsageSnapshot } from "@/lib/agent-usage";
import { accountStoreFetch } from "@/lib/account-store";
import { getRequestSession } from "@/lib/api-auth";
import { isSameOrigin, hashPassword } from "@/lib/session";

function jsonResponse(body: unknown, status = 200) {
  return NextResponse.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

export async function GET() {
  const session = await getRequestSession();
  if (!session || session.role !== "admin") {
    return jsonResponse({ error: "Authentication required." }, 401);
  }
  try {
    const response = await accountStoreFetch("internal/accounts");
    return new Response(await response.arrayBuffer(), {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("content-type") ?? "application/json",
        "Cache-Control": "no-store",
      },
    });
  } catch {
    return jsonResponse({ error: "Account store is unavailable." }, 503);
  }
}

export async function POST(request: Request) {
  const session = await getRequestSession();
  if (!session || session.role !== "admin") {
    return jsonResponse({ error: "Authentication required." }, 401);
  }
  if (!isSameOrigin(request)) {
    return jsonResponse({ error: "Invalid request origin." }, 403);
  }

  let payload: unknown;
  try {
    const text = await request.text();
    if (text.length > 8192) {
      return jsonResponse({ error: "Request body is too large." }, 413);
    }
    payload = JSON.parse(text);
  } catch {
    return jsonResponse({ error: "Invalid account details." }, 400);
  }
  if (
    typeof payload !== "object" ||
    payload === null ||
    !("username" in payload) ||
    typeof payload.username !== "string" ||
    !("password" in payload) ||
    typeof payload.password !== "string" ||
    payload.password.length < 12 ||
    payload.password.length > 1024 ||
    !("peerId" in payload) ||
    typeof payload.peerId !== "string" ||
    !/^[a-f0-9]{64}$/.test(payload.peerId) ||
    !("note" in payload) ||
    typeof payload.note !== "string" ||
    !("dailyQuotaBytes" in payload) ||
    !("monthlyQuotaBytes" in payload) ||
    !("uploadLimitMbps" in payload) ||
    !("downloadLimitMbps" in payload) ||
    !("maxConcurrentConnections" in payload) ||
    !("accessWindow" in payload)
  ) {
    return jsonResponse({ error: "Invalid account details." }, 400);
  }

  const { password, ...details } = payload;
  try {
    const snapshot = await getAgentUsageSnapshot();
    const assignmentBaseline = baselineForPeer(snapshot, payload.peerId);
    const response = await accountStoreFetch("internal/accounts", "POST", {
      ...details,
      passwordHash: hashPassword(password),
      assignmentBaseline,
    });
    return new Response(await response.arrayBuffer(), {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("content-type") ?? "application/json",
        "Cache-Control": "no-store",
      },
    });
  } catch (error) {
    if (error instanceof AgentUsageError) {
      return jsonResponse({ error: error.message }, error.status);
    }
    return jsonResponse({ error: "Account store is unavailable." }, 503);
  }
}
