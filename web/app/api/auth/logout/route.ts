import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { accountStoreFetch } from "@/lib/account-store";
import {
  isSameOrigin,
  SESSION_COOKIE,
  verifySessionToken,
} from "@/lib/session";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) {
    return NextResponse.json({ error: "Invalid request origin." }, { status: 403 });
  }

  const cookieStore = await cookies();
  const session = verifySessionToken(cookieStore.get(SESSION_COOKIE)?.value);
  let sessionRevoked = !session;
  let status = 200;
  if (session) {
    try {
      const revokeResponse = await accountStoreFetch(
        "internal/session/logout",
        "POST",
        {
          role: session.role,
          subject: session.subject,
          accountId: session.accountId ?? null,
          authVersion: session.authVersion,
        },
      );
      sessionRevoked = revokeResponse.ok;
      if (!revokeResponse.ok) status = 503;
    } catch {
      status = 503;
    }
  }

  const response = NextResponse.json(
    { authenticated: false, sessionRevoked },
    { status },
  );
  response.cookies.set(SESSION_COOKIE, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 0,
  });
  return response;
}
