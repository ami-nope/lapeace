import { NextResponse } from "next/server";
import {
  createSessionToken,
  isSameOrigin,
  SESSION_COOKIE,
  SESSION_SECONDS,
  verifyAdminCredentials,
} from "@/lib/session";

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

  if (!process.env.PANEL_SESSION_SECRET || !process.env.PANEL_ADMIN_PASSWORD_HASH) {
    return NextResponse.json(
      { error: "Administrator authentication is not configured." },
      { status: 503 },
    );
  }

  if (!verifyAdminCredentials(body.adminId, body.password)) {
    return NextResponse.json({ error: "Access denied." }, { status: 401 });
  }

  const token = createSessionToken();
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
