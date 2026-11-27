import { cookies } from "next/headers";
import { accountStoreFetch } from "@/lib/account-store";
import { SESSION_COOKIE, verifySessionToken } from "@/lib/session";

export async function getRequestSession() {
  const cookieStore = await cookies();
  const session = verifySessionToken(cookieStore.get(SESSION_COOKIE)?.value);
  if (!session) return null;

  try {
    const response = await accountStoreFetch("internal/session/validate", "POST", {
      role: session.role,
      subject: session.subject,
      accountId: session.accountId ?? null,
      authVersion: session.authVersion,
    });
    if (!response.ok) return null;
    const result = (await response.json()) as { valid?: unknown };
    return result.valid === true ? session : null;
  } catch {
    return null;
  }
}
