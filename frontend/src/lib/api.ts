// HTTP client for the MIZAR API. The per-launch token comes from a meta tag that the
// backend fills when it serves this page; state-changing requests must send it.

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details: Record<string, unknown> = {},
    public readonly requestId: string | null = null,
  ) {
    super(message);
  }
}

function token(): string {
  return document.querySelector('meta[name="mizar-token"]')?.getAttribute("content") ?? "";
}

export type Query = Record<string, string | number | boolean | null | undefined>;

export function withQuery(path: string, query?: Query): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `${path}?${text}` : path;
}

async function toError(response: Response): Promise<ApiError> {
  try {
    const body = await response.json();
    const error = body?.error;
    if (error?.code) {
      return new ApiError(response.status, error.code, error.message, error.details ?? {}, error.request_id ?? null);
    }
  } catch {
    // fall through
  }
  return new ApiError(response.status, "HTTP_ERROR", `Request failed with status ${response.status}.`);
}

export async function api<T>(
  path: string,
  options: { method?: string; body?: unknown; query?: Query; signal?: AbortSignal } = {},
): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") headers["X-MIZAR-Token"] = token();
  let body: BodyInit | undefined;
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  let response: Response;
  try {
    response = await fetch(withQuery(path, options.query), { method, headers, body, signal: options.signal });
  } catch (exc) {
    if ((exc as Error).name === "AbortError") throw exc;
    throw new ApiError(0, "NETWORK_ERROR", "MIZAR is not reachable. Is `mizar serve` running?");
  }
  if (!response.ok) throw await toError(response);
  return (response.status === 204 ? undefined : await response.json()) as T;
}

/** Upload one file as the raw request body, reporting progress (fetch cannot). */
export function uploadFile(
  caseId: string,
  file: File,
  params: Query,
  onProgress: (fraction: number) => void,
): Promise<{ source_file: { source_file_id: string }; job_id: string }> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", withQuery(`/api/cases/${encodeURIComponent(caseId)}/files`, { filename: file.name, ...params }));
    request.setRequestHeader("X-MIZAR-Token", token());
    request.setRequestHeader("Content-Type", "application/octet-stream");
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total);
    };
    request.onerror = () => reject(new ApiError(0, "NETWORK_ERROR", "The upload was interrupted."));
    request.onload = () => {
      let body: unknown = null;
      try {
        body = JSON.parse(request.responseText);
      } catch {
        // non-JSON response
      }
      if (request.status >= 200 && request.status < 300) {
        resolve(body as { source_file: { source_file_id: string }; job_id: string });
        return;
      }
      const error = (body as { error?: { code: string; message: string; details?: Record<string, unknown>; request_id?: string } } | null)?.error;
      reject(
        new ApiError(
          request.status,
          error?.code ?? "HTTP_ERROR",
          error?.message ?? `Upload failed with status ${request.status}.`,
          error?.details ?? {},
          error?.request_id ?? null,
        ),
      );
    };
    request.send(file);
  });
}
