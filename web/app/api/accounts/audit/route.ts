import { NextResponse } from "next/server";
import { accountStoreFetch } from "@/lib/account-store";
import { getRequestSession } from "@/lib/api-auth";

export async function GET() {
  const session = await getRequestSession();
  if (!session || session.role !== "admin") {
    return NextResponse.json(
      { error: "Authentication required." },
      { status: 401, headers: { "Cache-Control": "no-store" } },
    );
  }
  try {
    const response = await accountStoreFetch("internal/audit");
    return new Response(await response.arrayBuffer(), {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("content-type") ?? "application/json",
        "Cache-Control": "no-store",
      },
    });
  } catch {
    return NextResponse.json(
      { error: "Audit log is unavailable." },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
}
