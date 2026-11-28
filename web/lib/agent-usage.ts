import {
  isUsageSnapshot,
  istDate,
  type UsageBaseline,
  type UsageSnapshot,
} from "@/lib/usage-accounting";

export class AgentUsageError extends Error {
  constructor(
    message: string,
    readonly status = 503,
  ) {
    super(message);
    this.name = "AgentUsageError";
  }
}

export async function getAgentUsageSnapshot(): Promise<UsageSnapshot> {
  const baseUrl = process.env.AGENT_BASE_URL;
  const apiToken = process.env.AGENT_API_TOKEN;
  if (!baseUrl || !apiToken) {
    throw new AgentUsageError("The VPS agent is not configured.");
  }

  let target: URL;
  try {
    target = new URL("/api/v1/snapshot", baseUrl);
  } catch {
    throw new AgentUsageError("The VPS agent address is invalid.");
  }
  if (
    target.protocol !== "https:" &&
    target.hostname !== "localhost" &&
    target.hostname !== "127.0.0.1"
  ) {
    throw new AgentUsageError("The VPS agent must use HTTPS.");
  }

  let response: Response;
  try {
    response = await fetch(target, {
      headers: { Authorization: `Bearer ${apiToken}` },
      cache: "no-store",
      signal: AbortSignal.timeout(7_000),
    });
  } catch (error) {
    if (error instanceof TypeError || error instanceof DOMException) {
      throw new AgentUsageError("The VPS agent could not be reached.", 502);
    }
    throw error;
  }
  if (!response.ok) {
    throw new AgentUsageError(
      "The VPS agent returned an error.",
      response.status,
    );
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new AgentUsageError("The VPS agent returned invalid telemetry.", 502);
  }
  if (!isUsageSnapshot(payload)) {
    throw new AgentUsageError("The VPS agent returned invalid telemetry.", 502);
  }
  return payload;
}

export function baselineForPeer(
  snapshot: UsageSnapshot,
  peerId: string,
  now = new Date(),
): UsageBaseline {
  if (istDate(snapshot.sampledAt) !== istDate(now)) {
    throw new AgentUsageError(
      "The VPS agent has no sample from the current IST day.",
    );
  }
  const peer = snapshot.peers.find((record) => record.id === peerId);
  if (!peer) {
    throw new AgentUsageError(
      "Telemetry for the selected VPN peer is unavailable.",
    );
  }
  return {
    peerId,
    sampledAt: snapshot.sampledAt,
    uploadBytes: peer.dailyUploadBytes,
    downloadBytes: peer.dailyDownloadBytes,
  };
}
