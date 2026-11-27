import { NextResponse } from "next/server";
import {
  createSessionToken,
  isSameOrigin,
  SESSION_COOKIE,
  SESSION_SECONDS,
  verifyAdminCredentials,
  verifyScryptPassword,
} from "@/lib/session";
import { accountStoreFetch } from "@/lib/account-store";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) {
    return NextResponse.json({ error: "Invalid request origin." }, { status: 403 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch (error) {
    if (error instanceof SyntaxError) {
      return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
    }
    throw error;
  }

  if (
    typeof body !== "object" ||
    body === null ||
    !("adminId" in body) ||
    !("password" in body) ||
    typeof body.adminId !== "string" ||
    typeof body.password !== "string" ||
    body.adminId.length > 128 ||
    body.password.length > 1024
  ) {
    return NextResponse.json({ error: "Invalid credentials." }, { status: 400 });
  }

  if (
    !process.env.PANEL_SESSION_SECRET ||
    !process.env.PANEL_ADMIN_ID ||
    !process.env.PANEL_ADMIN_PASSWORD_HASH ||
    !process.env.ACCOUNT_STORE_API_URL ||
    !process.env.ACCOUNT_STORE_TOKEN
  ) {
    return NextResponse.json(
      { error: "Authentication is not configured." },
      { status: 503 },
    );
  }

  let rateLimitResponse: Response;
  try {
    rateLimitResponse = await accountStoreFetch("internal/login/check", "POST", {
      identifier: body.adminId,
    });
  } catch {
    return NextResponse.json(
      { error: "Authentication service is unavailable." },
      { status: 503 },
    );
  }
  if (rateLimitResponse.status === 429) {
    return NextResponse.json(
      { error: "Too many attempts. Try again later." },
      { status: 429 },
    );
  }
  if (!rateLimitResponse.ok) {
    return NextResponse.json(
      { error: "Authentication service is unavailable." },
      { status: 503 },
    );
  }

  let sessionClaims:
    | { subject: string; role: "admin" }
    | { subject: string; role: "user"; accountId: string }
    | null = null;
  if (body.adminId === process.env.PANEL_ADMIN_ID) {
    if (verifyAdminCredentials(body.adminId, body.password)) {
      sessionClaims = { subject: body.adminId, role: "admin" };
    }
  } else {
    try {
      const lookupResponse = await accountStoreFetch(
        "internal/login/lookup",
        "POST",
        { username: body.adminId },
      );
      if (lookupResponse.ok) {
        const result = (await lookupResponse.json()) as {
          account?: {
            id: string;
            status: "active" | "suspended";
            passwordHash: string;
          } | null;
        };
        if (
          result.account?.status === "active" &&
          verifyScryptPassword(body.password, result.account.passwordHash)
        ) {
          sessionClaims = {
            subject: result.account.id,
            role: "user",
            accountId: result.account.id,
          };
        }
      } else if (lookupResponse.status !== 400) {
        return NextResponse.json(
          { error: "Authentication service is unavailable." },
          { status: 503 },
        );
      }
    } catch {
      return NextResponse.json(
        { error: "Authentication service is unavailable." },
        { status: 503 },
      );
    }
  }

  let finishResponse: Response;
  try {
    finishResponse = await accountStoreFetch("internal/login/finish", "POST", {
      identifier: body.adminId,
      success: sessionClaims !== null,
    });
  } catch {
    return NextResponse.json(
      { error: "Authentication service is unavailable." },
      { status: 503 },
    );
  }
  if (!finishResponse.ok) {
    return NextResponse.json(
      { error: "Authentication service is unavailable." },
      { status: 503 },
    );
  }

  if (!sessionClaims) {
    return NextResponse.json({ error: "Access denied." }, { status: 401 });
  }

  const token = createSessionToken(sessionClaims);
  if (!token) {
    return NextResponse.json(
      { error: "Session signing is not configured." },
      { status: 503 },
    );
  }

  const response = NextResponse.json({ authenticated: true });
  response.cookies.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: SESSION_SECONDS,
  });
  return response;
}
