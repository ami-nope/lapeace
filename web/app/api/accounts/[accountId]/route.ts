import { NextResponse } from "next/server";
import { accountStoreFetch } from "@/lib/account-store";
import { getRequestSession } from "@/lib/api-auth";
import { isSameOrigin, hashPassword } from "@/lib/session";

type RouteContext = { params: Promise<{ accountId: string }> };

function jsonResponse(body: unknown, status = 200) {
  return NextResponse.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

export async function PATCH(request: Request, context: RouteContext) {
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
    return jsonResponse({ error: "Invalid account update." }, 400);
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return jsonResponse({ error: "Invalid account update." }, 400);
  }
  const { password, ...updates } = payload as Record<string, unknown>;
  if (
    password !== undefined &&
    (typeof password !== "string" || password.length < 12 || password.length > 1024)
  ) {
    return jsonResponse({ error: "Password must be at least 12 characters." }, 400);
  }
  if (password !== undefined) {
    Object.assign(updates, { passwordHash: hashPassword(password) });
  }

  const { accountId } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(accountId)) {
    return jsonResponse({ error: "Account not found." }, 404);
  }
  try {
    const response = await accountStoreFetch(
      `internal/accounts/${encodeURIComponent(accountId)}`,
      "PATCH",
      updates,
    );
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

export async function DELETE(request: Request, context: RouteContext) {
  const session = await getRequestSession();
  if (!session || session.role !== "admin") {
    return jsonResponse({ error: "Authentication required." }, 401);
  }
  if (!isSameOrigin(request)) {
    return jsonResponse({ error: "Invalid request origin." }, 403);
  }
  const { accountId } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(accountId)) {
    return jsonResponse({ error: "Account not found." }, 404);
  }
  try {
    const response = await accountStoreFetch(
      `internal/accounts/${encodeURIComponent(accountId)}`,
      "DELETE",
    );
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
