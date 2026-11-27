"use client";

import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  Cable,
  CircleHelp,
  Clock3,
  FileKey2,
  Gauge,
  HardDrive,
  LayoutDashboard,
  LogOut,
  Plus,
  RefreshCw,
  Shield,
  Signal,
  Users,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { AdminAccounts } from "@/components/admin-accounts";

type Peer = {
  id: string;
  fingerprint: string;
  allowedIps: string[];
  status: "connected" | "idle";
  rxBytes: number;
  txBytes: number;
  rxBps: number;
  txBps: number;
  handshakeAt: number | null;
  todayBytes: number;
};

type Snapshot = {
  interface: {
    name: string;
    status: "online" | "offline";
    rxBytes: number;
    txBytes: number;
    rxBps: number;
    txBps: number;
  };
  sampledAt: string;
  peers: Peer[];
  history: { date: string; rxBytes: number; txBytes: number }[];
};

type PanelEvent = {
  at: string;
  message: string;
  level: "info" | "warning";
};

type DynamicIpRecord = {
  ip: string;
  firstRegisteredAt: string;
  lastUsedAt: string;
  registrationSource: string;
  status: "active" | "expired";
};

type DynamicSyncStatus = {
  syncedAt: string;
  status: "ok" | "degraded" | "error";
  added: number;
  removed: number;
  message: string;
};

type DynamicSSHData = {
  currentIp: string | null;
  ipError: string | null;
  registrationStatus: "active" | "expired" | "not_registered";
  lastSuccessfulRegistration: string | null;
  lastVpsSync: DynamicSyncStatus | null;
  records: DynamicIpRecord[];
};

type UserSummary = {
  sampledAt: string;
  todayBytes: number;
  uploadBps: number;
  downloadBps: number;
  dailyQuotaBytes: number | null;
};

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "NEVER";
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? "—" : timestamp.toLocaleString();
}

function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || !Number.isFinite(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
}

function formatRate(bytesPerSecond: number | null | undefined): string {
  return bytesPerSecond == null ? "—" : `${formatBytes(bytesPerSecond)}/s`;
}

function formatAge(timestamp: number | null): string {
  if (!timestamp) return "NEVER";
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - timestamp));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function Metric({
  label,
  value,
  detail,
  icon: Icon,
  accent = "text-[#65d98a]",
}: {
  label: string;
  value: string;
  detail: string;
  icon: typeof Users;
  accent?: string;
}) {
  return (
    <section className="panel min-w-0 px-3 py-3">
      <div className="flex items-start justify-between">
        <p className="mono-label">{label}</p>
        <Icon className={`h-3.5 w-3.5 ${accent}`} aria-hidden="true" />
      </div>
      <p className="mt-2 truncate text-lg leading-6 text-[#c5d5c7]">{value}</p>
      <p className="mt-1 truncate text-[9px] text-[#718276]">{detail}</p>
    </section>
  );
}

function TrafficGraph({ snapshot }: { snapshot: Snapshot | null }) {
  const points = useMemo(() => {
    const history = snapshot?.history ?? [];
    if (history.length < 2) return null;
    const max = Math.max(1, ...history.map((item) => item.rxBytes + item.txBytes));
    const plot = (value: number, index: number) => {
      const x = (index / Math.max(1, history.length - 1)) * 100;
      const y = 90 - (value / max) * 78;
      return `${index === 0 ? "M" : "L"} ${x.toFixed(2)} ${y.toFixed(2)}`;
    };
    return {
      rx: history.map((item, index) => plot(item.rxBytes, index)).join(" "),
      tx: history.map((item, index) => plot(item.txBytes, index)).join(" "),
      labels: history,
    };
  }, [snapshot]);

  return (
    <section className="panel">
      <div className="panel-heading">
        <span className="flex items-center gap-2">
          <Activity className="h-3.5 w-3.5 text-[#65d98a]" aria-hidden="true" />
          Transfer history
        </span>
        <span className="text-[9px] text-[#718276]">DAILY / 14D</span>
      </div>
      <div className="p-3">
        {points ? (
          <>
            <div className="h-[150px] border border-[#26382b] bg-[#090d0a] p-2">
              <svg
                aria-label="Daily client upload and download history"
                className="h-full w-full"
                preserveAspectRatio="none"
                role="img"
                viewBox="0 0 100 100"
              >
                {[12, 32, 52, 72, 92].map((y) => (
                  <line
                    key={y}
                    x1="0"
                    x2="100"
                    y1={y}
                    y2={y}
                    stroke="#26382b"
                    strokeDasharray="1 1"
                    vectorEffect="non-scaling-stroke"
                  />
                ))}
                <path d={points.rx} fill="none" stroke="#65d98a" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
                <path d={points.tx} fill="none" stroke="#d8a64e" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
              </svg>
            </div>
            <div className="mt-2 flex justify-between text-[9px] text-[#718276]">
              <span>{points.labels[0]?.date ?? "—"}</span>
              <span className="flex gap-3">
                <span className="text-[#65d98a]">■ UPLOAD</span>
                <span className="text-[#d8a64e]">■ DOWNLOAD</span>
              </span>
              <span>{points.labels[points.labels.length - 1]?.date ?? "—"}</span>
            </div>
          </>
        ) : (
          <div className="flex h-[178px] items-center justify-center border border-dashed border-[#26382b] bg-[#090d0a] px-4 text-center text-[10px] text-[#718276]">
            History will appear after the authenticated agent has collected samples.
          </div>
        )}
      </div>
    </section>
  );
}

export function Dashboard({ role }: { role: "admin" | "user" }) {
  const router = useRouter();
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [events, setEvents] = useState<PanelEvent[]>([]);
  const [dynamicSsh, setDynamicSsh] = useState<DynamicSSHData | null>(null);
  const [userSummary, setUserSummary] = useState<UserSummary | null>(null);
  const [dynamicError, setDynamicError] = useState("");
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [registeringIp, setRegisteringIp] = useState(false);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    if (role === "user") {
      try {
        const response = await fetch("/api/panel/summary", { cache: "no-store" });
        if (response.status === 401) {
          router.replace("/login");
          return;
        }
        if (!response.ok) {
          const result = (await response.json()) as { error?: string };
          setError(result.error ?? `Account returned HTTP ${response.status}.`);
          setUserSummary(null);
          return;
        }
        setUserSummary((await response.json()) as UserSummary);
        setError("");
      } catch {
        setError("Account telemetry is unavailable.");
        setUserSummary(null);
      } finally {
        setRefreshing(false);
      }
      return;
    }

    try {
      const [snapshotResponse, eventsResponse, dynamicResponse] = await Promise.all([
        fetch("/api/panel/snapshot", { cache: "no-store" }),
        fetch("/api/panel/events", { cache: "no-store" }),
        fetch("/api/dynamic-ssh", { cache: "no-store" }).catch(() => null),
      ]);
      if (snapshotResponse.status === 401 || dynamicResponse?.status === 401) {
        router.replace("/login");
        return;
      }
      if (dynamicResponse?.ok) {
        setDynamicSsh((await dynamicResponse.json()) as DynamicSSHData);
        setDynamicError("");
      } else {
        setDynamicError("Dynamic SSH registry is unavailable.");
      }
      if (!snapshotResponse.ok) {
        const result = (await snapshotResponse.json()) as { error?: string };
        setError(result.error ?? `Agent returned HTTP ${snapshotResponse.status}.`);
        setSnapshot(null);
        return;
      }
      const data = (await snapshotResponse.json()) as Snapshot;
      setSnapshot(data);
      setLastUpdated(new Date().toLocaleTimeString());
      setError("");
      if (eventsResponse.ok) {
        setEvents((await eventsResponse.json()) as PanelEvent[]);
      }
    } catch {
      setSnapshot(null);
      setError("VPS agent unreachable. Check the authenticated agent connection.");
    } finally {
      setRefreshing(false);
    }
  }, [role, router]);

  async function registerCurrentIp() {
    setRegisteringIp(true);
    setDynamicError("");
    try {
      const response = await fetch("/api/dynamic-ssh/register", {
        method: "POST",
      });
      if (response.status === 401) {
        router.replace("/login");
        return;
      }
      if (!response.ok) {
        const result = (await response.json()) as { error?: string };
        setDynamicError(result.error ?? "IP registration failed.");
        return;
      }
      const statusResponse = await fetch("/api/dynamic-ssh", { cache: "no-store" });
      if (statusResponse.status === 401) {
        router.replace("/login");
        return;
      }
      if (!statusResponse.ok) {
        setDynamicError("IP registered, but status refresh failed.");
        return;
      }
      setDynamicSsh((await statusResponse.json()) as DynamicSSHData);
    } catch {
      setDynamicError("Dynamic SSH API is unreachable.");
    } finally {
      setRegisteringIp(false);
    }
  }

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

  const peers = snapshot?.peers ?? [];
  const todayBytes = peers.reduce((total, peer) => total + peer.todayBytes, 0);

  if (role === "user") {
    const dailyQuota = userSummary?.dailyQuotaBytes ?? null;
    const remaining = dailyQuota === null
      ? null
      : Math.max(0, dailyQuota - (userSummary?.todayBytes ?? 0));
    const quotaPercent = dailyQuota && dailyQuota > 0
      ? Math.min(100, ((userSummary?.todayBytes ?? 0) / dailyQuota) * 100)
      : 0;
    return (
      <main className="min-h-screen bg-[#090d0a] px-3 py-5 sm:px-6">
        <div className="mx-auto max-w-4xl space-y-3">
          <header className="flex items-center justify-between border border-[#26382b] bg-[#0c120e] px-4 py-3">
            <div>
              <p className="text-[11px] tracking-[0.12em] text-[#c5d5c7]">
                <span className="text-[#65d98a]">AMII</span> // PRIVATE LINK
              </p>
              <p className="mt-1 text-[9px] text-[#718276]">DAILY USAGE CONSOLE</p>
            </div>
            <Button onClick={() => void logout()} size="small" variant="quiet">
              <LogOut className="h-3 w-3" aria-hidden="true" /> SIGN OUT
            </Button>
          </header>

          <section className="panel p-4 sm:p-5">
            <p className="mono-label">Welcome back</p>
            <h1 className="mt-1 text-sm text-[#c5d5c7]">
              Hey there—your link is ready. Here are today’s numbers; keep it smooth.
            </h1>
            <p aria-live="polite" className="mt-2 min-h-4 text-[10px] text-[#d8a64e]">
              {error}
            </p>
          </section>

          <div className="grid gap-3 md:grid-cols-3">
            <Metric
              label="Data used today"
              value={formatBytes(userSummary?.todayBytes)}
              detail="UPLOAD + DOWNLOAD"
              icon={HardDrive}
            />
            <Metric
              label="Current upload"
              value={formatRate(userSummary?.uploadBps)}
              detail="LIVE RATE"
              icon={ArrowUpFromLine}
            />
            <Metric
              label="Current download"
              value={formatRate(userSummary?.downloadBps)}
              detail="LIVE RATE"
              icon={ArrowDownToLine}
              accent="text-[#d8a64e]"
            />
          </div>

          <section className="panel p-4">
            <div className="flex flex-wrap items-end justify-between gap-2">
              <div>
                <p className="mono-label">Today’s quota</p>
                <p className="mt-1 text-sm text-[#c5d5c7]">
                  {dailyQuota === null
                    ? `${formatBytes(userSummary?.todayBytes)} USED · NO DAILY CAP`
                    : `${formatBytes(userSummary?.todayBytes)} USED · ${formatBytes(remaining)} REMAINING`}
                </p>
              </div>
              {dailyQuota !== null && (
                <p className="text-[10px] text-[#718276]">LIMIT {formatBytes(dailyQuota)}</p>
              )}
            </div>
            {dailyQuota !== null && (
              <div
                aria-label={`Daily usage ${Math.round(quotaPercent)} percent`}
                aria-valuemax={100}
                aria-valuemin={0}
                aria-valuenow={Math.round(quotaPercent)}
                className="mt-3 h-2 border border-[#26382b] bg-[#090d0a]"
                role="progressbar"
              >
                <div
                  className="h-full bg-[#65d98a]"
                  style={{ width: `${quotaPercent}%` }}
                />
              </div>
            )}
            <p className="mt-3 text-[9px] text-[#718276]">
              Usage and limits are informational; this portal does not throttle or disconnect your VPN.
            </p>
            <p className="mt-2 text-[9px] text-[#718276]">
              LAST SAMPLE {formatTimestamp(userSummary?.sampledAt)}
            </p>
          </section>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[#090d0a]">
      <div className="flex min-h-screen flex-col lg:flex-row">
        <aside className="flex w-full shrink-0 flex-col border-b border-[#26382b] bg-[#0c120e] lg:min-h-screen lg:w-[208px] lg:border-b-0 lg:border-r">
          <div className="flex h-12 items-center justify-between border-b border-[#26382b] px-4">
            <a href="/" className="text-[11px] tracking-[0.12em] text-[#c5d5c7]">
              <span className="text-[#65d98a]">AMII</span> // NOC
            </a>
            <span className="text-[9px] text-[#718276]">v0.1</span>
          </div>
          <nav aria-label="Main navigation" className="flex gap-1 overflow-x-auto p-2 lg:flex-1 lg:flex-col">
            <a className="flex h-8 shrink-0 items-center gap-2 border border-[#26382b] bg-[#151e17] px-2.5 text-[10px] text-[#65d98a]" href="#overview" aria-current="page">
              <LayoutDashboard className="h-3.5 w-3.5" aria-hidden="true" /> OVERVIEW
            </a>
            <a className="flex h-8 shrink-0 items-center gap-2 px-2.5 text-[10px] text-[#718276] hover:text-[#c5d5c7]" href="#peers">
              <Users className="h-3.5 w-3.5" aria-hidden="true" /> PEERS
            </a>
            <a className="flex h-8 shrink-0 items-center gap-2 px-2.5 text-[10px] text-[#718276] hover:text-[#c5d5c7]" href="#traffic">
              <Activity className="h-3.5 w-3.5" aria-hidden="true" /> TRAFFIC
            </a>
            <a className="flex h-8 shrink-0 items-center gap-2 px-2.5 text-[10px] text-[#718276] hover:text-[#c5d5c7]" href="#events">
              <HardDrive className="h-3.5 w-3.5" aria-hidden="true" /> EVENT LOG
            </a>
            <a className="flex h-8 shrink-0 items-center gap-2 px-2.5 text-[10px] text-[#718276] hover:text-[#c5d5c7]" href="#accounts">
              <Users className="h-3.5 w-3.5" aria-hidden="true" /> ACCOUNTS
            </a>
          </nav>
          <div className="hidden border-t border-[#26382b] p-3 lg:block">
            <p className="mono-label">Management plane</p>
            <p className="mt-1 flex items-center text-[9px] text-[#d8a64e]">
              <span className="status-dot" /> NO WRITE ACCESS
            </p>
          </div>
        </aside>

        <div className="min-w-0 flex-1">
          <header className="flex min-h-12 flex-wrap items-center justify-between gap-2 border-b border-[#26382b] bg-[#0c120e] px-4 py-2 sm:px-5">
            <div className="flex items-center gap-2 text-[10px]">
              <Cable className="h-3.5 w-3.5 text-[#65d98a]" aria-hidden="true" />
              <span className="text-[#718276]">INTERFACE</span>
              <span>awg0</span>
              <span className="text-[#26382b]">|</span>
              <span className="text-[#718276]">HOST</span>
              <span>AMII-NODE</span>
            </div>
            <div className="flex items-center gap-3">
              <span className={`flex items-center text-[9px] ${snapshot?.interface.status === "online" ? "text-[#65d98a]" : "text-[#d8a64e]"}`}>
                <span className="status-dot" />
                {snapshot?.interface.status === "online" ? "AGENT LINKED" : "AGENT OFFLINE"}
              </span>
              <Button onClick={() => void refresh()} size="small" variant="outline" aria-label="Refresh dashboard">
                <RefreshCw className={`h-3 w-3 ${refreshing ? "animate-spin" : ""}`} aria-hidden="true" />
                <span className="hidden sm:inline">POLL</span>
              </Button>
              <Button onClick={() => void logout()} size="small" variant="quiet" aria-label="Sign out">
                <LogOut className="h-3 w-3" aria-hidden="true" />
                <span className="hidden sm:inline">EXIT</span>
              </Button>
            </div>
          </header>

          <div className="mx-auto max-w-[1500px] space-y-4 p-3 sm:p-5">
            <section id="overview" className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <p className="mono-label">AmneziaWG // operations</p>
                <h1 className="mt-1 text-base font-medium tracking-wide">Network overview</h1>
              </div>
              <p className="flex items-center gap-1.5 text-[9px] text-[#718276]">
                <Clock3 className="h-3 w-3" aria-hidden="true" />
                {lastUpdated ? `LAST SAMPLE ${lastUpdated}` : "AWAITING FIRST SAMPLE"}
              </p>
            </section>

            {error && (
              <div className="flex items-start gap-2 border border-[#654138] bg-[#1a100e] px-3 py-2 text-[10px] text-[#e2a095]" role="alert">
                <CircleHelp className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Metric label="Active peers" value={snapshot ? String(peers.filter((peer) => peer.status === "connected").length) : "—"} detail={snapshot ? `${peers.length} configured on ${snapshot.interface.name}` : "WAITING FOR AGENT"} icon={Users} />
              <Metric label="Transferred today" value={snapshot ? formatBytes(todayBytes) : "—"} detail="UPLOAD + DOWNLOAD / IST DAY" icon={ArrowDownToLine} />
              <Metric label="Upload throughput" value={formatRate(snapshot?.interface.rxBps)} detail={`PEER AGGREGATE ${formatBytes(snapshot?.interface.rxBytes)}`} icon={ArrowUpFromLine} accent="text-[#d8a64e]" />
              <Metric label="Download throughput" value={formatRate(snapshot?.interface.txBps)} detail={`PEER AGGREGATE ${formatBytes(snapshot?.interface.txBytes)}`} icon={ArrowDownToLine} />
            </div>

            <section className="flex flex-wrap items-center justify-between gap-2 border border-[#5a482a] bg-[#17140e] px-3 py-2">
              <div className="flex items-start gap-2">
                <Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#d8a64e]" aria-hidden="true" />
                <p className="text-[10px] leading-5 text-[#c9b88e]">
                  Peer changes are locked until the existing AWG persistence is inspected. This panel is read-only.
                </p>
              </div>
              <Button disabled size="small" variant="outline" title="Enable after AWG persistence review">
                <Plus className="h-3 w-3" aria-hidden="true" /> ADD PEER
              </Button>
            </section>

            <section className="panel" aria-labelledby="dynamic-ssh-title">
              <div className="panel-heading">
                <span id="dynamic-ssh-title" className="flex items-center gap-2">
                  <Shield className="h-3.5 w-3.5 text-[#d8a64e]" aria-hidden="true" />
                  Dynamic SSH access
                </span>
                <span className="text-[9px] text-[#718276]">WARP EXCLUSION REGISTRY</span>
              </div>
              <div className="grid gap-3 p-3 lg:grid-cols-[minmax(230px,0.8fr)_minmax(0,1.2fr)]">
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2">
                    <div className="border border-[#26382b] bg-[#090d0a] p-2.5">
                      <p className="mono-label">Detected public IPv4</p>
                      <p className="mt-1 break-all text-[12px] text-[#c5d5c7]">
                        {dynamicSsh?.currentIp ?? "UNAVAILABLE"}
                      </p>
                    </div>
                    <div className="border border-[#26382b] bg-[#090d0a] p-2.5">
                      <p className="mono-label">Registration status</p>
                      <p className={`mt-1 text-[10px] ${dynamicSsh?.registrationStatus === "active" ? "text-[#65d98a]" : "text-[#d8a64e]"}`}>
                        {(dynamicSsh?.registrationStatus ?? "unknown").replace("_", " ").toUpperCase()}
                      </p>
                    </div>
                    <div className="border border-[#26382b] bg-[#090d0a] p-2.5">
                      <p className="mono-label">Last successful registration</p>
                      <p className="mt-1 text-[9px] text-[#9caf9e]">
                        {formatTimestamp(dynamicSsh?.lastSuccessfulRegistration)}
                      </p>
                    </div>
                    <div className="border border-[#26382b] bg-[#090d0a] p-2.5">
                      <p className="mono-label">Last VPS synchronization</p>
                      <p className="mt-1 text-[9px] text-[#9caf9e]">
                        {formatTimestamp(dynamicSsh?.lastVpsSync?.syncedAt)}
                      </p>
                      {dynamicSsh?.lastVpsSync && (
                        <p className={`mt-1 text-[9px] ${dynamicSsh.lastVpsSync.status === "ok" ? "text-[#65d98a]" : "text-[#d8a64e]"}`}>
                          {dynamicSsh.lastVpsSync.status.toUpperCase()} · +{dynamicSsh.lastVpsSync.added} / −{dynamicSsh.lastVpsSync.removed}
                        </p>
                      )}
                    </div>
                  </div>
                  <Button
                    className="w-full"
                    disabled={!dynamicSsh?.currentIp || registeringIp}
                    onClick={() => void registerCurrentIp()}
                    variant="outline"
                  >
                    {registeringIp ? "REGISTERING…" : "REGISTER MY CURRENT IP"}
                  </Button>
                  <p aria-live="polite" className="min-h-4 text-[9px] text-[#d8a64e]">
                    {dynamicError || dynamicSsh?.ipError || ""}
                  </p>
                </div>

                <div className="min-w-0 border border-[#26382b] bg-[#090d0a]">
                  <div className="flex justify-between border-b border-[#26382b] px-3 py-2">
                    <span className="mono-label">Registered dynamic IPs</span>
                    <span className="text-[9px] text-[#718276]">{dynamicSsh?.records.length ?? 0} RECORDS</span>
                  </div>
                  <div className="max-h-52 overflow-y-auto">
                    {dynamicSsh?.records.length ? (
                      <ul className="divide-y divide-[#1e2b21]">
                        {dynamicSsh.records.map((record) => {
                          const expiryTime =
                            Date.parse(record.lastUsedAt) + 15 * 24 * 60 * 60 * 1000;
                          const expiryAt = Number.isFinite(expiryTime)
                            ? new Date(expiryTime).toISOString()
                            : "";
                          return (
                            <li className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 px-3 py-2" key={record.ip}>
                              <div className="min-w-0">
                                <p className="truncate text-[11px] text-[#c5d5c7]">{record.ip}</p>
                                <p className="mt-0.5 text-[9px] text-[#718276]">
                                  LAST USED {formatTimestamp(record.lastUsedAt)}
                                </p>
                                <p className="text-[9px] text-[#718276]">
                                  EXPIRES {formatTimestamp(expiryAt)} · {record.registrationSource}
                                </p>
                              </div>
                              <span className={`self-center text-[9px] ${record.status === "active" ? "text-[#65d98a]" : "text-[#d8a64e]"}`}>
                                {record.status.toUpperCase()}
                              </span>
                            </li>
                          );
                        })}
                      </ul>
                    ) : (
                      <p className="px-3 py-5 text-center text-[10px] text-[#718276]">
                        No dynamic IPs registered.
                      </p>
                    )}
                  </div>
                </div>
              </div>
            </section>

            <AdminAccounts
              peers={peers.map(({ id, fingerprint, allowedIps }) => ({
                id,
                fingerprint,
                allowedIps,
              }))}
            />

            <div className="grid gap-3 xl:grid-cols-[minmax(0,1.75fr)_minmax(280px,0.8fr)]">
              <section id="peers" className="panel min-w-0">
                <div className="panel-heading">
                  <span className="flex items-center gap-2">
                    <Signal className="h-3.5 w-3.5 text-[#65d98a]" aria-hidden="true" /> Peer table
                  </span>
                  <span className="text-[9px] text-[#718276]">{snapshot ? `${peers.length} ENTRIES` : "NO TELEMETRY"}</span>
                </div>
                <div className="scroll-table">
                  <table className="w-full min-w-[860px] border-collapse text-left text-[10px]">
                    <thead>
                      <tr className="border-b border-[#26382b] text-[9px] text-[#718276]">
                        <th className="px-3 py-2 font-normal">PUBLIC KEY FINGERPRINT</th>
                        <th className="px-3 py-2 font-normal">CLIENT IP</th>
                        <th className="px-3 py-2 font-normal">STATE</th>
                        <th className="px-3 py-2 font-normal">UPLOAD / DOWNLOAD</th>
                        <th className="px-3 py-2 font-normal">TODAY</th>
                        <th className="px-3 py-2 font-normal">RATE</th>
                        <th className="px-3 py-2 font-normal">HANDSHAKE</th>
                        <th className="px-3 py-2 font-normal">CONTROL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {peers.map((peer) => (
                        <tr className="border-b border-[#1e2b21] last:border-0" key={peer.id}>
                          <td className="px-3 py-2.5 font-mono text-[#c5d5c7]">{peer.fingerprint}</td>
                          <td className="px-3 py-2.5 text-[#9caf9e]">{peer.allowedIps.join(", ") || "—"}</td>
                          <td className="px-3 py-2.5">
                            <span className={peer.status === "connected" ? "text-[#65d98a]" : "text-[#718276]"}>
                              <span className="status-dot" />{peer.status.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 leading-5 text-[#9caf9e]">
                            <div>↑ UP {formatBytes(peer.rxBytes)}</div>
                            <div>↓ DOWN {formatBytes(peer.txBytes)}</div>
                          </td>
                          <td className="px-3 py-2.5 text-[#9caf9e]">{formatBytes(peer.todayBytes)}</td>
                          <td className="px-3 py-2.5 leading-5 text-[#9caf9e]">
                            <div>↑ UP {formatRate(peer.rxBps)}</div>
                            <div>↓ DOWN {formatRate(peer.txBps)}</div>
                          </td>
                          <td className="px-3 py-2.5 text-[#9caf9e]">{formatAge(peer.handshakeAt)}</td>
                          <td className="px-3 py-2.5">
                            <Button disabled size="small" variant="quiet" title="Peer controls await configuration inspection">LOCKED</Button>
                          </td>
                        </tr>
                      ))}
                      {peers.length === 0 && (
                        <tr>
                          <td className="px-3 py-8 text-center text-[10px] text-[#718276]" colSpan={8}>
                            {snapshot ? "No peers reported by the interface." : "Peer records appear here when the agent is connected."}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>

              <div id="traffic">
                <TrafficGraph snapshot={snapshot} />
              </div>
            </div>

            <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <section className="panel">
                <div className="panel-heading">
                  <span className="flex items-center gap-2"><Gauge className="h-3.5 w-3.5 text-[#d8a64e]" aria-hidden="true" /> Usage accounting</span>
                  <span className="text-[9px] text-[#718276]">JSON SNAPSHOTS</span>
                </div>
                <div className="grid grid-cols-2 divide-x divide-[#26382b]">
                  <div className="p-3">
                    <p className="mono-label">Accounting status</p>
                    <p className="mt-1 text-[11px]">{snapshot ? "SAMPLING" : "NOT CONNECTED"}</p>
                  </div>
                  <div className="p-3">
                    <p className="mono-label">Persistence</p>
                    <p className="mt-1 text-[11px]">LOCAL JSON / AGENT</p>
                  </div>
                </div>
              </section>
              <section id="events" className="panel">
                <div className="panel-heading">
                  <span className="flex items-center gap-2"><FileKey2 className="h-3.5 w-3.5 text-[#65d98a]" aria-hidden="true" /> System events</span>
                  <span className="text-[9px] text-[#718276]">LATEST 12</span>
                </div>
                <ul className="max-h-40 divide-y divide-[#1e2b21] overflow-y-auto">
                  {events.map((event, index) => (
                    <li className="flex gap-3 px-3 py-2 text-[9px]" key={`${event.at}-${index}`}>
                      <time className="shrink-0 text-[#718276]">{new Date(event.at).toLocaleTimeString()}</time>
                      <span className={event.level === "warning" ? "text-[#d8a64e]" : "text-[#9caf9e]"}>{event.message}</span>
                    </li>
                  ))}
                  {events.length === 0 && (
                    <li className="px-3 py-4 text-[10px] text-[#718276]">No agent events received.</li>
                  )}
                </ul>
              </section>
            </div>

            <footer className="flex flex-wrap justify-between gap-2 border-t border-[#26382b] pt-3 text-[9px] text-[#718276]">
              <span>AMII CONTROL TERMINAL // SINGLE ADMIN</span>
              <span>API ROUTED SERVER-SIDE // PRIVATE KEY MATERIAL NEVER DISPLAYED</span>
            </footer>
          </div>
        </div>
      </div>
    </main>
  );
}
