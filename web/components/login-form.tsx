"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { KeyRound, LockKeyhole } from "lucide-react";
import { Button } from "@/components/ui/button";

export function LoginForm() {
  const router = useRouter();
  const [adminId, setAdminId] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId, password }),
      });
      if (!response.ok) {
        const result = (await response.json()) as { error?: string };
        setError(result.error ?? "Authentication failed.");
        return;
      }
      router.replace("/");
      router.refresh();
    } catch {
      setError("Authentication endpoint unavailable.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="terminal-grid relative flex min-h-screen items-center justify-center px-4 py-10">
      <div className="scanline absolute inset-0" aria-hidden="true" />
      <section
        aria-labelledby="login-title"
        className="relative w-full max-w-[410px] border border-[#354839] bg-[#0c120e]"
      >
        <div className="flex items-center justify-between border-b border-[#26382b] px-4 py-3">
          <div className="flex items-center gap-2 text-[10px] tracking-[0.12em] text-[#c5d5c7]">
            <span className="text-[#65d98a]">AMII</span>
            <span className="text-[#718276]">//</span>
            <span>NETWORK CONTROL</span>
          </div>
          <span className="text-[9px] text-[#718276]">AUTH GATE 01</span>
        </div>

        <div className="px-6 pb-6 pt-7 sm:px-8">
          <div className="mb-6 flex items-start justify-between">
            <div>
              <p className="mono-label mb-2">Private operations terminal</p>
              <h1 id="login-title" className="text-sm font-medium tracking-wide">
                Administrator sign-in
              </h1>
            </div>
            <LockKeyhole className="mt-1 h-4 w-4 text-[#65d98a]" aria-hidden="true" />
          </div>

          <div className="mb-6 grid grid-cols-2 border border-[#26382b] bg-[#090d0a]">
            <div className="border-r border-[#26382b] px-3 py-2">
              <p className="mono-label">Host</p>
              <p className="mt-1 text-[10px] text-[#c5d5c7]">amii-node / awg0</p>
            </div>
            <div className="px-3 py-2">
              <p className="mono-label">Access</p>
              <p className="mt-1 flex items-center text-[10px] text-[#d8a64e]">
                <span className="status-dot" />
                AUTH REQUIRED
              </p>
            </div>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <label className="block">
              <span className="mono-label mb-1.5 block">Administrator ID</span>
              <span className="flex h-9 items-center border border-[#354839] bg-[#090d0a] px-2.5 focus-within:border-[#65d98a]">
                <KeyRound className="mr-2 h-3.5 w-3.5 text-[#718276]" aria-hidden="true" />
                <input
                  autoComplete="username"
                  className="w-full bg-transparent text-[11px] text-[#c5d5c7] outline-none placeholder:text-[#56665a]"
                  maxLength={128}
                  onChange={(event) => setAdminId(event.target.value)}
                  placeholder="operator"
                  required
                  value={adminId}
                />
              </span>
            </label>

            <label className="block">
              <span className="mono-label mb-1.5 block">Passphrase</span>
              <input
                autoComplete="current-password"
                className="h-9 w-full border border-[#354839] bg-[#090d0a] px-2.5 text-[11px] text-[#c5d5c7] outline-none placeholder:text-[#56665a] focus:border-[#65d98a]"
                maxLength={1024}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="••••••••••••"
                required
                type="password"
                value={password}
              />
            </label>

            <div aria-live="polite" className="min-h-4 text-[10px] text-[#d67668]">
              {error}
            </div>

            <Button className="w-full" disabled={busy} type="submit">
              {busy ? "Verifying credentials..." : "Authenticate"}
            </Button>
          </form>

          <div className="mt-6 border-t border-[#26382b] pt-3 text-[9px] leading-5 text-[#718276]">
            <p>SESSION POLICY: HTTP-ONLY / SAME-SITE STRICT</p>
            <p>UNAUTHORIZED ACCESS IS REJECTED</p>
          </div>
        </div>
      </section>
    </main>
  );
}
