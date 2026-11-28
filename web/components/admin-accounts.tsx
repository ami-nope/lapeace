"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import type { AuditRecord, PortalAccount } from "@/lib/accounts";

type PeerOption = {
  id: string;
  fingerprint: string;
  allowedIps: string[];
};

type ManagedPeer = {
  clientId: string;
  label: string;
  address: string;
  status: "active" | "paused";
};

function isManagedPeer(value: unknown): value is ManagedPeer {
  return (
    typeof value === "object" &&
    value !== null &&
    "clientId" in value &&
    typeof value.clientId === "string" &&
    /^[a-f0-9]{64}$/.test(value.clientId) &&
    "label" in value &&
    typeof value.label === "string" &&
    "address" in value &&
    typeof value.address === "string" &&
    "status" in value &&
    (value.status === "active" || value.status === "paused")
  );
}

type AuditResult = {
  events: AuditRecord[];
  retentionDays: number;
  failedLoginCount: number;
};

type AccountEditor = {
  id: string;
  username: string;
  peerId: string;
  note: string;
  dailyQuota: string;
  monthlyQuota: string;
  uploadLimit: string;
  downloadLimit: string;
  connectionLimit: string;
  windowStart: string;
  windowEnd: string;
  newPassword: string;
};

const GIB = 1024 ** 3;

function bytesFromGiB(value: string): number | null {
  if (!value) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0
    ? Math.round(parsed * GIB)
    : null;
}

function formatQuota(value: number | null): string {
  if (value === null) return "NO CAP";
  return `${(value / GIB).toFixed(value % GIB === 0 ? 0 : 1)} GiB`;
}

function quotaInput(value: number | null): string {
  return value === null ? "" : (value / GIB).toString();
}

export function AdminAccounts({ peers }: { peers: PeerOption[] }) {
  const [accounts, setAccounts] = useState<PortalAccount[]>([]);
  const [managedPeers, setManagedPeers] = useState<ManagedPeer[]>([]);
  const [audit, setAudit] = useState<AuditResult | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [peerError, setPeerError] = useState("");
  const [peerNotice, setPeerNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [peerBusy, setPeerBusy] = useState<string | null>(null);
  const [peerLabel, setPeerLabel] = useState("");
  const [qrPeerId, setQrPeerId] = useState<string | null>(null);
  const [assignmentTargets, setAssignmentTargets] = useState<Record<string, string>>({});
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [peerId, setPeerId] = useState("");
  const [note, setNote] = useState("");
  const [dailyQuota, setDailyQuota] = useState("");
  const [monthlyQuota, setMonthlyQuota] = useState("");
  const [uploadLimit, setUploadLimit] = useState("");
  const [downloadLimit, setDownloadLimit] = useState("");
  const [connectionLimit, setConnectionLimit] = useState("");
  const [windowStart, setWindowStart] = useState("");
  const [windowEnd, setWindowEnd] = useState("");
  const [editing, setEditing] = useState<AccountEditor | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [accountsResponse, auditResponse] = await Promise.all([
        fetch("/api/accounts", { cache: "no-store" }),
        fetch("/api/accounts/audit", { cache: "no-store" }),
      ]);
      if (accountsResponse.status === 401) {
        window.location.assign("/login");
        return;
      }
      if (!accountsResponse.ok) {
        const result = (await accountsResponse.json()) as { error?: string };
        throw new Error(result.error ?? "Could not load accounts.");
      }
      const accountResult = (await accountsResponse.json()) as {
        accounts: PortalAccount[];
      };
      setAccounts(accountResult.accounts);
      if (auditResponse.ok) {
        setAudit((await auditResponse.json()) as AuditResult);
      }
      try {
        const managedResponse = await fetch("/api/panel/clients", {
          cache: "no-store",
        });
        if (!managedResponse.ok) {
          const result = (await managedResponse.json()) as {
            error?: string;
            detail?: string;
          };
          throw new Error(
            result.error ?? result.detail ?? "Could not load managed peers.",
          );
        }
        const managedResult = (await managedResponse.json()) as {
          clients?: unknown;
        };
        if (
          !Array.isArray(managedResult.clients) ||
          !managedResult.clients.every(isManagedPeer)
        ) {
          throw new Error("The agent returned invalid managed peer data.");
        }
        setManagedPeers(managedResult.clients);
        setPeerError("");
      } catch (caught) {
        setManagedPeers([]);
        setPeerError(
          caught instanceof Error
            ? caught.message
            : "Managed peer service unavailable.",
        );
      }
      setError("");
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "Account service unavailable.",
      );
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const accountPeers = peers.map((peer) => ({
    ...peer,
    allowedIps: [...peer.allowedIps],
  }));
  for (const managedPeer of managedPeers) {
    const existing = accountPeers.find((peer) => peer.id === managedPeer.clientId);
    if (existing) {
      existing.allowedIps = [managedPeer.address];
    } else {
      accountPeers.push({
        id: managedPeer.clientId,
        fingerprint: managedPeer.clientId.slice(0, 16),
        allowedIps: [managedPeer.address],
      });
    }
  }

  async function createPeer(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPeerBusy("create");
    setPeerError("");
    setPeerNotice("");
    try {
      const response = await fetch("/api/panel/clients", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label: peerLabel }),
      });
      if (!response.ok) {
        const result = (await response.json()) as {
          error?: string;
          detail?: string;
        };
        throw new Error(
          result.error ?? result.detail ?? `Peer creation failed (${response.status}).`,
        );
      }
      setPeerLabel("");
      setPeerNotice("Peer created. Download its config or show the QR code.");
      await refresh();
    } catch (caught) {
      setPeerError(
        caught instanceof Error ? caught.message : "Peer service unavailable.",
      );
    } finally {
      setPeerBusy(null);
    }
  }

  async function assignPeer(peer: ManagedPeer) {
    const targetAccountId =
      accounts.find((account) => account.peerId === peer.clientId)?.id ??
      assignmentTargets[peer.clientId] ??
      "";
    const account = accounts.find((item) => item.id === targetAccountId);
    if (!account) {
      setPeerError("Select an account to assign this peer to.");
      return;
    }
    if (account.peerId === peer.clientId) {
      setPeerNotice(`${peer.label} is already assigned to ${account.username}.`);
      return;
    }
    setPeerBusy(peer.clientId);
    setPeerError("");
    setPeerNotice("");
    try {
      const response = await fetch(`/api/accounts/${account.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ peerId: peer.clientId }),
      });
      if (!response.ok) {
        const result = (await response.json()) as { error?: string };
        throw new Error(result.error ?? "Could not assign peer to account.");
      }
      setPeerNotice(`Assigned ${peer.label} to ${account.username}.`);
      await refresh();
    } catch (caught) {
      setPeerError(
        caught instanceof Error ? caught.message : "Account service unavailable.",
      );
    } finally {
      setPeerBusy(null);
    }
  }

  async function changePeerStatus(
    peer: ManagedPeer,
    action: "pause" | "resume" | "revoke" | "regenerate",
  ) {
    const assignedAccount = accounts.find((account) => account.peerId === peer.clientId);
    if (action === "revoke" || action === "regenerate") {
      if (assignedAccount) {
        setPeerError(
          `Reassign ${peer.label} from ${assignedAccount.username} before ${action === "revoke" ? "revoking" : "regenerating"} it.`,
        );
        return;
      }
      const prompt =
        action === "revoke"
          ? `Permanently revoke ${peer.label}?`
          : `Regenerate keys for ${peer.label}? Its current config will stop working.`;
      if (!window.confirm(prompt)) return;
    }

    setPeerBusy(peer.clientId);
    setPeerError("");
    setPeerNotice("");
    try {
      const response = await fetch(
        `/api/panel/clients/${peer.clientId}${action === "revoke" ? "" : `/${action}`}`,
        { method: action === "revoke" ? "DELETE" : "POST" },
      );
      if (!response.ok) {
        const result = (await response.json()) as {
          error?: string;
          detail?: string;
        };
        throw new Error(
          result.error ?? result.detail ?? `Peer ${action} failed (${response.status}).`,
        );
      }
      setPeerNotice(
        action === "revoke"
          ? `Revoked ${peer.label}.`
          : action === "regenerate"
            ? `Regenerated keys for ${peer.label}; download its new config.`
            : `${peer.label} ${action === "pause" ? "paused" : "resumed"}.`,
      );
      if (qrPeerId === peer.clientId) setQrPeerId(null);
      await refresh();
    } catch (caught) {
      setPeerError(
        caught instanceof Error ? caught.message : "Peer service unavailable.",
      );
    } finally {
      setPeerBusy(null);
    }
  }

  async function createAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    const body = {
      username,
      password,
      peerId,
      note,
      dailyQuotaBytes: bytesFromGiB(dailyQuota),
      monthlyQuotaBytes: bytesFromGiB(monthlyQuota),
      uploadLimitMbps: uploadLimit ? Number(uploadLimit) : null,
      downloadLimitMbps: downloadLimit ? Number(downloadLimit) : null,
      maxConcurrentConnections: connectionLimit ? Number(connectionLimit) : null,
      accessWindow:
        windowStart && windowEnd
          ? {
              start: windowStart,
              end: windowEnd,
              timeZone: "Asia/Kolkata",
            }
          : null,
    };
    try {
      const response = await fetch("/api/accounts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const result = (await response.json()) as { error?: string };
      if (!response.ok) {
        setError(result.error ?? `Account creation failed (${response.status}).`);
        return;
      }
      setNotice("Account created. The password is stored as a one-way hash.");
      setUsername("");
      setPassword("");
      setPeerId("");
      setNote("");
      setDailyQuota("");
      setMonthlyQuota("");
      setUploadLimit("");
      setDownloadLimit("");
      setConnectionLimit("");
      setWindowStart("");
      setWindowEnd("");
      await refresh();
    } catch {
      setError("Account service is unreachable.");
    } finally {
      setBusy(false);
    }
  }

  async function setAccountStatus(account: PortalAccount) {
    setError("");
    setNotice("");
    try {
      const response = await fetch(`/api/accounts/${account.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: account.status === "active" ? "suspended" : "active",
        }),
      });
      if (!response.ok) {
        const result = (await response.json()) as { error?: string };
        setError(result.error ?? "Could not update account status.");
        return;
      }
      setNotice(
        account.status === "active"
          ? "Account suspended. Portal access is blocked."
          : "Account reactivated.",
      );
      await refresh();
    } catch {
      setError("Account service is unreachable.");
    }
  }

  function startEditing(account: PortalAccount) {
    setEditing({
      id: account.id,
      username: account.username,
      peerId: account.peerId,
      note: account.note,
      dailyQuota: quotaInput(account.dailyQuotaBytes),
      monthlyQuota: quotaInput(account.monthlyQuotaBytes),
      uploadLimit: account.uploadLimitMbps?.toString() ?? "",
      downloadLimit: account.downloadLimitMbps?.toString() ?? "",
      connectionLimit: account.maxConcurrentConnections?.toString() ?? "",
      windowStart: account.accessWindow?.start ?? "",
      windowEnd: account.accessWindow?.end ?? "",
      newPassword: "",
    });
    setError("");
    setNotice("");
  }

  async function saveAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editing) return;
    if (Boolean(editing.windowStart) !== Boolean(editing.windowEnd)) {
      setError("Enter both access-window times or leave both blank.");
      return;
    }
    setError("");
    setNotice("");
    setBusy(true);
    const body = {
      note: editing.note,
      ...(editing.peerId !== accounts.find((account) => account.id === editing.id)?.peerId
        ? { peerId: editing.peerId }
        : {}),
      dailyQuotaBytes: bytesFromGiB(editing.dailyQuota),
      monthlyQuotaBytes: bytesFromGiB(editing.monthlyQuota),
      uploadLimitMbps: editing.uploadLimit ? Number(editing.uploadLimit) : null,
      downloadLimitMbps: editing.downloadLimit ? Number(editing.downloadLimit) : null,
      maxConcurrentConnections: editing.connectionLimit
        ? Number(editing.connectionLimit)
        : null,
      accessWindow:
        editing.windowStart && editing.windowEnd
          ? {
              start: editing.windowStart,
              end: editing.windowEnd,
              timeZone: "Asia/Kolkata",
            }
          : null,
      ...(editing.newPassword ? { password: editing.newPassword } : {}),
    };
    try {
      const response = await fetch(`/api/accounts/${editing.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const result = (await response.json()) as { error?: string };
      if (!response.ok) {
        setError(result.error ?? `Account update failed (${response.status}).`);
        return;
      }
      setNotice(`Updated ${editing.username}.`);
      setEditing(null);
      await refresh();
    } catch {
      setError("Account service is unreachable.");
    } finally {
      setBusy(false);
    }
  }

  async function deleteAccount(account: PortalAccount) {
    if (!window.confirm(`Permanently delete account ${account.username}?`)) return;
    setError("");
    setNotice("");
    try {
      const response = await fetch(`/api/accounts/${account.id}`, {
        method: "DELETE",
      });
      if (!response.ok) {
        const result = (await response.json()) as { error?: string };
        setError(result.error ?? "Could not delete account.");
        return;
      }
      setNotice("Account deleted; its AWG peer was not modified.");
      await refresh();
    } catch {
      setError("Account service is unreachable.");
    }
  }

  return (
    <section id="accounts" className="panel" aria-labelledby="accounts-title">
      <div className="panel-heading">
        <span id="accounts-title">Portal accounts</span>
        <span className="text-[9px] text-[#718276]">
          {accounts.length} ACCOUNTS · DISPLAY-ONLY POLICY
        </span>
      </div>
      <div className="space-y-3 border-b border-[#26382b] p-3">
        <form className="flex flex-wrap items-end gap-2" onSubmit={createPeer}>
          <label className="min-w-48 flex-1">
            <span className="mono-label mb-1 block">Create AmneziaWG peer · label</span>
            <input
              className="h-8 w-full border border-[#354839] bg-[#090d0a] px-2 text-[10px] outline-none focus:border-[#65d98a]"
              maxLength={48}
              minLength={1}
              onChange={(event) => setPeerLabel(event.target.value)}
              pattern="[A-Za-z0-9 _.-]+"
              required
              value={peerLabel}
            />
          </label>
          <Button disabled={peerBusy !== null} size="small" type="submit">
            {peerBusy === "create" ? "CREATING…" : "CREATE PEER"}
          </Button>
        </form>
        {peerError && (
          <p className="text-[9px] text-[#e2a095]" role="alert">{peerError}</p>
        )}
        {peerNotice && (
          <p className="text-[9px] text-[#65d98a]" role="status">{peerNotice}</p>
        )}
        <div className="overflow-x-auto border border-[#26382b] bg-[#090d0a]">
          <table className="w-full min-w-[900px] text-left text-[10px]">
            <thead>
              <tr className="border-b border-[#26382b] text-[9px] text-[#718276]">
                <th className="px-3 py-2 font-normal">MANAGED PEER</th>
                <th className="px-3 py-2 font-normal">VPN IP</th>
                <th className="px-3 py-2 font-normal">ACCOUNT ASSIGNMENT</th>
                <th className="px-3 py-2 font-normal">LIFECYCLE</th>
                <th className="px-3 py-2 font-normal">CONFIG</th>
              </tr>
            </thead>
            <tbody>
              {managedPeers.map((peer) => {
                const owner = accounts.find((account) => account.peerId === peer.clientId);
                const targetAccountId =
                  owner?.id ?? assignmentTargets[peer.clientId] ?? "";
                return (
                  <tr className="border-b border-[#1e2b21] last:border-0" key={peer.clientId}>
                    <td className="px-3 py-2">
                      <div className="text-[#c5d5c7]">{peer.label}</div>
                      <div className="mt-0.5 text-[9px] text-[#718276]">{peer.clientId.slice(0, 16)}…</div>
                      <div className={peer.status === "active" ? "mt-1 text-[9px] text-[#65d98a]" : "mt-1 text-[9px] text-[#d8a64e]"}>
                        {peer.status.toUpperCase()}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-[#9caf9e]">{peer.address}</td>
                    <td className="px-3 py-2">
                      <div className="flex gap-1">
                        <select
                          aria-label={`Account assignment for ${peer.label}`}
                          className="h-7 min-w-32 border border-[#354839] bg-[#111813] px-1 text-[9px]"
                          onChange={(event) =>
                            setAssignmentTargets({
                              ...assignmentTargets,
                              [peer.clientId]: event.target.value,
                            })
                          }
                          value={targetAccountId}
                        >
                          <option value="">SELECT ACCOUNT</option>
                          {accounts
                            .filter(
                              (account) =>
                                account.peerId === peer.clientId || !owner,
                            )
                            .map((account) => (
                              <option key={account.id} value={account.id}>
                                {account.username}
                              </option>
                            ))}
                        </select>
                        <Button
                          disabled={
                            peerBusy !== null ||
                            !targetAccountId ||
                            owner?.id === targetAccountId
                          }
                          onClick={() => void assignPeer(peer)}
                          size="small"
                          variant="quiet"
                        >
                          ASSIGN
                        </Button>
                      </div>
                      <span className="mt-1 block text-[9px] text-[#718276]">
                        {owner ? `ASSIGNED · ${owner.username}` : "UNASSIGNED"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex gap-1">
                        <Button
                          disabled={peerBusy !== null}
                          onClick={() =>
                            void changePeerStatus(
                              peer,
                              peer.status === "active" ? "pause" : "resume",
                            )
                          }
                          size="small"
                          variant="quiet"
                        >
                          {peer.status === "active" ? "PAUSE" : "RESUME"}
                        </Button>
                        <Button
                          disabled={peerBusy !== null || Boolean(owner)}
                          onClick={() => void changePeerStatus(peer, "regenerate")}
                          size="small"
                          title={owner ? "Reassign this peer first." : undefined}
                          variant="quiet"
                        >
                          REKEY
                        </Button>
                        <Button
                          disabled={peerBusy !== null || Boolean(owner)}
                          onClick={() => void changePeerStatus(peer, "revoke")}
                          size="small"
                          title={owner ? "Reassign this peer first." : undefined}
                          variant="quiet"
                        >
                          REVOKE
                        </Button>
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex gap-1">
                        <a
                          aria-disabled={peer.status !== "active"}
                          className={`inline-flex h-7 items-center border border-[#354839] px-2 text-[9px] text-[#9caf9e] hover:border-[#65d98a]${peer.status !== "active" ? " pointer-events-none opacity-40" : ""}`}
                          href={`/api/panel/clients/${peer.clientId}/config`}
                          tabIndex={peer.status === "active" ? 0 : -1}
                        >
                          DOWNLOAD
                        </a>
                        <Button
                          disabled={peer.status !== "active"}
                          onClick={() =>
                            setQrPeerId(qrPeerId === peer.clientId ? null : peer.clientId)
                          }
                          size="small"
                          variant="quiet"
                        >
                          {qrPeerId === peer.clientId ? "HIDE QR" : "SHOW QR"}
                        </Button>
                      </div>
                      {qrPeerId === peer.clientId && (
                        <div className="mt-2 border border-[#26382b] bg-white p-2">
                          <img
                            alt={`AmneziaWG configuration QR code for ${peer.label}`}
                            className="h-36 w-36"
                            src={`/api/panel/clients/${peer.clientId}/config/qr`}
                          />
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
              {!managedPeers.length && (
                <tr>
                  <td className="px-3 py-5 text-center text-[#718276]" colSpan={5}>
                    {peerError ? "MANAGED PEERS UNAVAILABLE" : "NO MANAGED PEERS"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
      <div className="grid gap-3 p-3 xl:grid-cols-[minmax(0,1.1fr)_minmax(280px,0.9fr)]">
        <div className="min-w-0">
          <div className="overflow-x-auto border border-[#26382b] bg-[#090d0a]">
            <table className="w-full min-w-[690px] text-left text-[10px]">
              <thead>
                <tr className="border-b border-[#26382b] text-[9px] text-[#718276]">
                  <th className="px-3 py-2 font-normal">ACCOUNT / NOTE</th>
                  <th className="px-3 py-2 font-normal">PEER</th>
                  <th className="px-3 py-2 font-normal">DAILY / MONTHLY</th>
                  <th className="px-3 py-2 font-normal">STATE</th>
                  <th className="px-3 py-2 font-normal">CONTROL</th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((account) => {
                  const peer = accountPeers.find((item) => item.id === account.peerId);
                  return (
                    <tr className="border-b border-[#1e2b21] last:border-0" key={account.id}>
                      <td className="px-3 py-2">
                        <div className="text-[#c5d5c7]">{account.username}</div>
                        <div className="mt-0.5 max-w-48 truncate text-[9px] text-[#718276]">
                          {account.note || "NO NOTE"}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-[#9caf9e]">
                        {peer?.allowedIps.join(", ") || peer?.fingerprint || account.peerId.slice(0, 12)}
                      </td>
                      <td className="px-3 py-2 text-[#9caf9e]">
                        {formatQuota(account.dailyQuotaBytes)} / {formatQuota(account.monthlyQuotaBytes)}
                      </td>
                      <td className={account.status === "active" ? "px-3 py-2 text-[#65d98a]" : "px-3 py-2 text-[#d8a64e]"}>
                        {account.status.toUpperCase()}
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex gap-1">
                          <Button
                            onClick={() => startEditing(account)}
                            size="small"
                            variant="quiet"
                          >
                            EDIT
                          </Button>
                          <Button
                            onClick={() => void setAccountStatus(account)}
                            size="small"
                            variant="quiet"
                          >
                            {account.status === "active" ? "SUSPEND" : "ACTIVATE"}
                          </Button>
                          <Button
                            onClick={() => void deleteAccount(account)}
                            size="small"
                            variant="quiet"
                          >
                            DELETE
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {!accounts.length && (
                  <tr>
                    <td className="px-3 py-5 text-center text-[#718276]" colSpan={5}>
                      No portal accounts created.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {editing && (
            <form
              className="mt-3 space-y-2 border border-[#354839] bg-[#111813] p-3"
              onSubmit={saveAccount}
            >
              <div className="flex items-center justify-between gap-2">
                <p className="mono-label">Edit {editing.username}</p>
                <button
                  className="text-[9px] text-[#718276] hover:text-[#c5d5c7]"
                  onClick={() => setEditing(null)}
                  type="button"
                >
                  CANCEL
                </button>
              </div>
              <label className="block">
                <span className="mono-label mb-1 block">Assigned existing peer</span>
                <select
                  className="h-8 w-full border border-[#354839] bg-[#090d0a] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                  onChange={(event) =>
                    setEditing({ ...editing, peerId: event.target.value })
                  }
                  required
                  value={editing.peerId}
                >
                  {!accountPeers.some((peer) => peer.id === editing.peerId) && (
                    <option value={editing.peerId}>
                      CURRENT PEER · {editing.peerId.slice(0, 12)} (TELEMETRY UNAVAILABLE)
                    </option>
                  )}
                  {accountPeers
                    .filter(
                      (peer) =>
                        (peer.id === editing.peerId ||
                          managedPeers.every(
                            (managedPeer) =>
                              managedPeer.clientId !== peer.id ||
                              managedPeer.status === "active",
                          )) &&
                        (peer.id === editing.peerId ||
                          !accounts.some(
                            (account) =>
                              account.id !== editing.id && account.peerId === peer.id,
                          )),
                    )
                    .map((peer) => (
                      <option key={peer.id} value={peer.id}>
                        {peer.allowedIps.join(", ") || peer.fingerprint}
                      </option>
                    ))}
                </select>
                <span className="mt-1 block text-[9px] text-[#718276]">
                  Changing peers starts a new usage-accounting period.
                </span>
              </label>
              <label className="block">
                <span className="mono-label mb-1 block">Admin note</span>
                <input
                  className="h-8 w-full border border-[#354839] bg-[#090d0a] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                  maxLength={240}
                  onChange={(event) =>
                    setEditing({ ...editing, note: event.target.value })
                  }
                  value={editing.note}
                />
              </label>
              <div className="grid grid-cols-2 gap-2">
                {([
                  ["Daily cap · GiB", "dailyQuota"],
                  ["Monthly cap · GiB", "monthlyQuota"],
                  ["Upload cap · Mbps", "uploadLimit"],
                  ["Download cap · Mbps", "downloadLimit"],
                  ["Connection limit · advisory", "connectionLimit"],
                ] as const).map(([label, field]) => (
                  <label className="block" key={field}>
                    <span className="mono-label mb-1 block">{label}</span>
                    <input
                      className="h-8 w-full border border-[#354839] bg-[#090d0a] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                      min={field === "connectionLimit" ? "1" : "0.1"}
                      max={field === "connectionLimit" ? "64" : undefined}
                      onChange={(event) =>
                        setEditing({ ...editing, [field]: event.target.value })
                      }
                      step={field === "connectionLimit" ? "1" : "0.1"}
                      type="number"
                      value={editing[field]}
                    />
                  </label>
                ))}
                <div className="grid grid-cols-2 gap-1">
                  <label className="block">
                    <span className="mono-label mb-1 block">Window start</span>
                    <input
                      className="h-8 w-full border border-[#354839] bg-[#090d0a] px-1 text-[10px] outline-none focus:border-[#65d98a]"
                      onChange={(event) =>
                        setEditing({ ...editing, windowStart: event.target.value })
                      }
                      type="time"
                      value={editing.windowStart}
                    />
                  </label>
                  <label className="block">
                    <span className="mono-label mb-1 block">Window end</span>
                    <input
                      className="h-8 w-full border border-[#354839] bg-[#090d0a] px-1 text-[10px] outline-none focus:border-[#65d98a]"
                      onChange={(event) =>
                        setEditing({ ...editing, windowEnd: event.target.value })
                      }
                      type="time"
                      value={editing.windowEnd}
                    />
                  </label>
                </div>
              </div>
              <label className="block">
                <span className="mono-label mb-1 block">Reset password · optional</span>
                <input
                  autoComplete="new-password"
                  className="h-8 w-full border border-[#354839] bg-[#090d0a] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                  minLength={12}
                  onChange={(event) =>
                    setEditing({ ...editing, newPassword: event.target.value })
                  }
                  type="password"
                  value={editing.newPassword}
                />
              </label>
              <p className="text-[9px] text-[#718276]">
                Policy values remain advisory and do not enforce traffic, connections, or access windows.
              </p>
              <Button disabled={busy} size="small" type="submit">
                SAVE ACCOUNT
              </Button>
            </form>
          )}

          <div className="mt-3 border border-[#26382b] bg-[#090d0a]">
            <div className="flex justify-between border-b border-[#26382b] px-3 py-2">
              <span className="mono-label">Security / admin activity</span>
              <span className="text-[9px] text-[#718276]">
                RETAINED {audit?.retentionDays ?? 3} DAYS
              </span>
            </div>
            {audit?.failedLoginCount ? (
              <p className="border-b border-[#26382b] px-3 py-2 text-[9px] text-[#d8a64e]">
                ALERT: {audit.failedLoginCount} FAILED LOGIN ATTEMPTS IN RETENTION WINDOW
              </p>
            ) : null}
            <ul className="max-h-32 divide-y divide-[#1e2b21] overflow-y-auto">
              {(audit?.events ?? []).slice(0, 8).map((entry) => (
                <li className="flex justify-between gap-2 px-3 py-1.5 text-[9px]" key={entry.id}>
                  <span className="text-[#9caf9e]">{entry.action.replaceAll("_", " ")} · {entry.subject}</span>
                  <time className="shrink-0 text-[#718276]" dateTime={entry.at}>
                    {new Date(entry.at).toLocaleString()}
                  </time>
                </li>
              ))}
              {!audit?.events.length && (
                <li className="px-3 py-3 text-center text-[9px] text-[#718276]">
                  No recent account events.
                </li>
              )}
            </ul>
          </div>
        </div>

        <form className="space-y-2 border border-[#26382b] bg-[#090d0a] p-3" onSubmit={createAccount}>
          <p className="mono-label">Create user account</p>
          <div className="grid gap-2 sm:grid-cols-2">
            <label className="block">
              <span className="mono-label mb-1 block">User ID</span>
              <input
                autoComplete="off"
                className="h-8 w-full border border-[#354839] bg-[#111813] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                maxLength={48}
                minLength={3}
                onChange={(event) => setUsername(event.target.value)}
                pattern="[A-Za-z0-9][A-Za-z0-9._-]{2,47}"
                required
                value={username}
              />
            </label>
            <label className="block">
              <span className="mono-label mb-1 block">Initial password · min 12 chars</span>
              <input
                autoComplete="new-password"
                className="h-8 w-full border border-[#354839] bg-[#111813] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                minLength={12}
                onChange={(event) => setPassword(event.target.value)}
                required
                type="password"
                value={password}
              />
            </label>
          </div>
          <label className="block">
            <span className="mono-label mb-1 block">Assigned existing peer</span>
            <select
              className="h-8 w-full border border-[#354839] bg-[#111813] px-2 text-[10px] outline-none focus:border-[#65d98a]"
              onChange={(event) => setPeerId(event.target.value)}
              required
              value={peerId}
            >
              <option value="">SELECT PEER</option>
              {accountPeers
                .filter(
                  (peer) =>
                    !accounts.some((account) => account.peerId === peer.id) &&
                    managedPeers.every(
                      (managedPeer) =>
                        managedPeer.clientId !== peer.id ||
                        managedPeer.status === "active",
                    ),
                )
                .map((peer) => (
                <option key={peer.id} value={peer.id}>
                  {peer.allowedIps.join(", ") || peer.fingerprint}
                </option>
                ))}
            </select>
          </label>
          <label className="block">
            <span className="mono-label mb-1 block">Admin note</span>
            <input
              className="h-8 w-full border border-[#354839] bg-[#111813] px-2 text-[10px] outline-none focus:border-[#65d98a]"
              maxLength={240}
              onChange={(event) => setNote(event.target.value)}
              value={note}
            />
          </label>
          <div className="grid grid-cols-2 gap-2">
            <label className="block">
              <span className="mono-label mb-1 block">Daily cap · GiB</span>
              <input
                className="h-8 w-full border border-[#354839] bg-[#111813] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                min="0.1"
                onChange={(event) => setDailyQuota(event.target.value)}
                step="0.1"
                type="number"
                value={dailyQuota}
              />
            </label>
            <label className="block">
              <span className="mono-label mb-1 block">Monthly cap · GiB</span>
              <input
                className="h-8 w-full border border-[#354839] bg-[#111813] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                min="0.1"
                onChange={(event) => setMonthlyQuota(event.target.value)}
                step="0.1"
                type="number"
                value={monthlyQuota}
              />
            </label>
            <label className="block">
              <span className="mono-label mb-1 block">Upload cap · Mbps</span>
              <input
                className="h-8 w-full border border-[#354839] bg-[#111813] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                min="0.1"
                onChange={(event) => setUploadLimit(event.target.value)}
                step="0.1"
                type="number"
                value={uploadLimit}
              />
            </label>
            <label className="block">
              <span className="mono-label mb-1 block">Download cap · Mbps</span>
              <input
                className="h-8 w-full border border-[#354839] bg-[#111813] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                min="0.1"
                onChange={(event) => setDownloadLimit(event.target.value)}
                step="0.1"
                type="number"
                value={downloadLimit}
              />
            </label>
            <label className="block">
              <span className="mono-label mb-1 block">Connection limit · advisory</span>
              <input
                className="h-8 w-full border border-[#354839] bg-[#111813] px-2 text-[10px] outline-none focus:border-[#65d98a]"
                min="1"
                max="64"
                onChange={(event) => setConnectionLimit(event.target.value)}
                type="number"
                value={connectionLimit}
              />
            </label>
            <div className="grid grid-cols-2 gap-1">
              <label className="block">
                <span className="mono-label mb-1 block">Window start</span>
                <input
                  className="h-8 w-full border border-[#354839] bg-[#111813] px-1 text-[10px] outline-none focus:border-[#65d98a]"
                  onChange={(event) => setWindowStart(event.target.value)}
                  type="time"
                  value={windowStart}
                />
              </label>
              <label className="block">
                <span className="mono-label mb-1 block">Window end</span>
                <input
                  className="h-8 w-full border border-[#354839] bg-[#111813] px-1 text-[10px] outline-none focus:border-[#65d98a]"
                  onChange={(event) => setWindowEnd(event.target.value)}
                  type="time"
                  value={windowEnd}
                />
              </label>
            </div>
          </div>
          <p className="text-[9px] leading-4 text-[#718276]">
            Quotas, speed caps, connection limits and time windows are advisory only; they do not alter VPN access.
          </p>
          <div aria-live="polite" className="min-h-4 text-[9px] text-[#d8a64e]">
            {error || notice}
          </div>
          <Button className="w-full" disabled={busy || accountPeers.length === 0} type="submit">
            {busy ? "CREATING…" : "CREATE USER"}
          </Button>
        </form>
      </div>
    </section>
  );
}
