// Typed fetch client. The per-launch bearer token lives in sessionStorage only (never localStorage / URL query).
export interface ApiErrorBody {
  code: string;
  message: string;
  request_id: string;
  retryable: boolean;
  details_safe: Record<string, unknown>;
}

export class ApiError extends Error {
  constructor(public status: number, public body: ApiErrorBody) {
    super(body.message);
  }
}

const KEY = "osintcc.token";
let base = ""; // "" => same-origin proxy (dev server); "http://127.0.0.1:<port>" inside the desktop shell

export function apiUrl(path: string): string {
  return `${base}/api/v1${path}`;
}

export function authHeader(): Record<string, string> {
  return { Authorization: `Bearer ${getToken()}` };
}

interface TauriGlobal { core: { invoke: (cmd: string) => Promise<{ port: number; token: string }> } }
export const inDesktopShell = (): boolean => !!(window as unknown as { __TAURI__?: TauriGlobal }).__TAURI__;

/** Desktop shell handshake: the port and token arrive via a Tauri command, never via the URL. */
export async function connectDesktopBackend(): Promise<void> {
  const t = (window as unknown as { __TAURI__: TauriGlobal }).__TAURI__;
  const info = await t.core.invoke("backend_info");
  base = `http://127.0.0.1:${info.port}`;
  setToken(info.token);
}

export function getToken(): string {
  try {
    const hash = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const fromHash = hash.get("token");
    if (fromHash) {
      sessionStorage.setItem(KEY, fromHash);
      history.replaceState(null, "", window.location.pathname + window.location.search); // scrub token from URL
    }
    return sessionStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
}

export function setToken(t: string): void {
  try {
    sessionStorage.setItem(KEY, t);
  } catch {
    /* storage unavailable: token stays in memory for this page load only */
  }
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${getToken()}`);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  let res: Response;
  try {
    res = await fetch(apiUrl(path), { ...init, headers, body });
  } catch {
    throw new ApiError(0, {
      code: "backend_unreachable", message: "Cannot reach the local backend. Is it running?",
      request_id: "-", retryable: true, details_safe: {},
    });
  }
  if (!res.ok) {
    let b: ApiErrorBody;
    try {
      b = await res.json();
    } catch {
      b = { code: "http_error", message: res.statusText, request_id: "-", retryable: false, details_safe: {} };
    }
    throw new ApiError(res.status, b);
  }
  return (res.headers.get("content-type")?.includes("json") ? res.json() : res.text()) as Promise<T>;
}

export interface CaseT { id: string; title: string; category: string; status: string; purpose: string; description: string;
  updated_at: string; finding_count?: number; }
export interface PlanStep { adapter_id: string; name: string; runnable: boolean; reason: string; requires_confirmation?: boolean;
  endpoints?: string[]; operation_class?: string; warnings?: string[]; rate_limit_per_minute?: number | null; cost?: string; health?: string; }
export interface Plan { target: { type: string; canonical: string; ambiguous_with: string[] }; steps: PlanStep[];
  warnings: string[]; offline: boolean; note: string; }
export interface FindingT { id: string; subject: string; subject_type: string; predicate: string; value: unknown; confidence: string;
  confidence_reason: string; adapter: string; adapter_version: string; evidence_id: string; source_url: string | null;
  observed_at: string; source_published_at: string | null; }
export interface RunT { id: string; status: string; jobs: { id: string; adapter_id: string; status: string; error_code: string | null;
  warnings: string[]; attempts: number }[]; }
export interface GraphT { nodes: { id: string; type: string; label: string; degree: number }[];
  edges: { id: string; source: string; target: string; type: string; status: string; confidence: string;
    confidence_reason: string; evidence_ids: string[] }[]; truncated: boolean; total_nodes: number; note: string; }
export interface ToolT { id: string; name: string; operation_class: string; description: string; license: string | null;
  supported_target_types: string[]; endpoints: string[]; install_hint: string | null; health: { status: string; version?: string; detail?: string } }
