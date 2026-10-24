/** Argon2id cost parameters. Mirrors `passbox_core::kdf::KdfParams`. */
export interface KdfParams {
  memoryKib: number;
  iterations: number;
  parallelism: number;
}

export interface Health {
  status: "ok";
}

export interface ServerMeta {
  name: string;
  version: string;
  apiVersion: number;
  minKdfParams: KdfParams;
}

/** Thrown when the server answers with a non-2xx status. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly path: string,
    readonly body: string,
  ) {
    super(`Passbox API request to ${path} failed with status ${status}`);
    this.name = "ApiError";
  }
}

export interface ClientOptions {
  /** Server origin, for example `https://passbox.example.com`. Defaults to the current origin. */
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
}

export interface PassboxClient {
  health(): Promise<Health>;
  meta(): Promise<ServerMeta>;
}

export function createClient(options: ClientOptions = {}): PassboxClient {
  const baseUrl = (options.baseUrl ?? "").replace(/\/+$/, "");
  const doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);

  async function getJson<T>(path: string): Promise<T> {
    const response = await doFetch(`${baseUrl}${path}`, {
      headers: { accept: "application/json" },
    });
    if (!response.ok) {
      throw new ApiError(response.status, path, await response.text());
    }
    return (await response.json()) as T;
  }

  return {
    health: () => getJson<Health>("/health"),
    meta: () => getJson<ServerMeta>("/api/v1/meta"),
  };
}
