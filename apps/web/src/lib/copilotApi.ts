import { ApiError, apiUrl, authHeader } from "./api";

export type Mode = "general" | "investigation" | "tutor";
export type Level = "beginner" | "advanced";

export interface Source { ref: string; source?: string; title?: string; kind?: string; id?: string; evidence_ids?: string[] }
export interface Step { rank: number; priority: number; title: string; why: string; go?: { route: string; tab?: string }; tool?: string; tool_id?: string; run_id?: string }
export interface Proposal {
  id: string; tool: string; case_id: string | null; status: "pending" | "approved" | "rejected" | "executed" | "failed";
  args: Record<string, unknown>; preview: Record<string, unknown>; result: Record<string, unknown>; sensitive: string; description: string;
}
export interface Msg {
  id?: string; role: "user" | "assistant" | "note"; mode: Mode; content: string;
  meta?: { sources?: Source[]; profile_citations?: { id: string; title: string; sha256: string }[]; warnings?: string[]; proposals?: string[]; steps?: Step[]; tools?: { name: string; ok: boolean; error?: string }[]; degraded?: string | null;
    model?: { name: string; model: string; local: boolean } | null; action_claim_flagged?: boolean; uncited?: boolean; intent?: string | null };
  pending?: boolean;
}
export interface ModelStatus {
  ai_enabled: boolean; ready: boolean; reason: string; fallback: string;
  active: { id: string; name: string; model: string; type: string; local: boolean } | null;
  profiles: { id: string; name: string; model: string; type: string; local: boolean }[];
}
export interface ConvResp { conversation: { id: string; mode: Mode } | null; messages: Msg[]; proposals: Proposal[]; skipped_corrupt: number }
export interface Approval { transfer_token: string; preview: { provider: string | null; model: string | null; approx_tokens: number; case_records_included: number;
  restricted_items_withheld: number; warning: string; messages: { role: string; content: string }[] } }

export interface ChatBody {
  text: string; mode: Mode; ctx: Record<string, unknown>; conversation_id?: string | null; profile_id?: string | null; level: Level;
  include_restricted?: boolean; transfer_token?: string | null; intent_hint?: "next_steps" | null; quick?: boolean;
}

export type StreamEvent =
  | { type: "meta"; conversation_id: string; mode: Mode; intent: string | null; skipped_corrupt: number; model: { active: ModelStatus["active"]; ready: boolean; reason: string; local: boolean } }
  | { type: "delta"; text: string }
  | { type: "tool"; name: string; ok: boolean; error?: string }
  | { type: "proposal"; proposal: Proposal }
  | { type: "approval_required"; transfer_token: string; preview: Approval["preview"] }
  | { type: "final"; text: string; sources: Source[]; warnings: string[]; message_id: string; steps?: Step[] | null; profile_citations?: { id: string; title: string; sha256: string }[] }
  | { type: "user_saved"; message_id: string }
  | { type: "done"; conversation_id: string; message_id: string; proposals: string[] }
  | { type: "error"; code: string; message: string };

/** POST /copilot/chat and yield each NDJSON event as it arrives. */
export async function* streamChat(body: ChatBody, signal?: AbortSignal): AsyncGenerator<StreamEvent> {
  let res: Response;
  try {
    res = await fetch(apiUrl("/copilot/chat"), { method: "POST", signal, headers: { ...authHeader(), "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } catch {
    throw new ApiError(0, { code: "backend_unreachable", message: "Cannot reach the local backend. Is it running?", request_id: "-", retryable: true, details_safe: {} });
  }
  if (!res.ok || !res.body) {
    let b;
    try { b = await res.json(); } catch { b = { code: "http_error", message: res.statusText, request_id: "-", retryable: false, details_safe: {} }; }
    throw new ApiError(res.status, b);
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try { yield JSON.parse(line) as StreamEvent; } catch { /* a damaged line is skipped, the rest of the stream continues */ }
    }
  }
  const tail = buf.trim();
  if (tail) { try { yield JSON.parse(tail) as StreamEvent; } catch { /* ignore */ } }
}
