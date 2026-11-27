export async function accountStoreFetch(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<Response> {
  const baseUrl = process.env.ACCOUNT_STORE_API_URL;
  const token = process.env.ACCOUNT_STORE_TOKEN;
  if (!baseUrl || !token || token.length < 32) {
    throw new Error("Account store is not configured.");
  }

  let base: URL;
  let target: URL;
  try {
    base = new URL(baseUrl);
    target = new URL(path.replace(/^\/+/, ""), `${baseUrl.replace(/\/+$/, "")}/`);
  } catch {
    throw new Error("Account store address is invalid.");
  }
  if (
    (base.protocol !== "https:" &&
      base.hostname !== "localhost" &&
      base.hostname !== "127.0.0.1") ||
    target.origin !== base.origin
  ) {
    throw new Error("Account store must use the configured HTTPS origin.");
  }

  const headers = new Headers({ Authorization: `Bearer ${token}` });
  let requestBody: string | undefined;
  if (body !== undefined) {
    headers.set("Content-Type", "application/json");
    requestBody = JSON.stringify(body);
  }
  return fetch(target, {
    method,
    headers,
    body: requestBody,
    cache: "no-store",
    signal: AbortSignal.timeout(7_000),
  });
}
