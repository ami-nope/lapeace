import { redirect } from "next/navigation";
import { Dashboard } from "@/components/dashboard";
import { getRequestSession } from "@/lib/api-auth";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const session = await getRequestSession();
  if (!session) {
    redirect("/login");
  }
  return <Dashboard role={session.role} />;
}
