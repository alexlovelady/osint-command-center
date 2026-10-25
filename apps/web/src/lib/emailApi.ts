// Types for Associated Emails and the cross-INT expansion plan. The server is the source of truth; these only describe its JSON.
export type EmailClass = "confirmed" | "likely" | "possible" | "rejected";
export interface EmailSource { id: string; kind: string; group: string; explicit: boolean; evidence_id: string | null; url: string; context: string; adapter: string; basis: string; observed_at: string; via: string }
export interface AssociatedEmailT { id: string; address: string; masked: boolean; classification: EmailClass; label: string; state: string; origin: string; origin_label: string; explanation: string[];
  confirmation_kind: string | null; conflicts: { kind: string; detail: string }[]; associations: { usernames: string[]; domains: string[]; documents: string[]; accounts: string[] }; aliases: string[];
  depth: number; origin_path: string[]; discovered_at: string; last_verified_at: string | null; reviewed_by: string | null; review_basis: string; note: string; is_input: boolean;
  exposure: { state: string; label: string; note: string; categories?: string[]; credential_indicator?: boolean; reports?: number; recommend?: string[] };
  sources: EmailSource[]; evidence: { id: string; title: string; kind: string; sha256: string; url: string | null }[] }
export interface EmailList { items: AssociatedEmailT[]; counts: Record<EmailClass, number>; duplicates: { key: string; ids: string[]; addresses: string[] }[]; legend: Record<EmailClass, string>; notice: string; role: string }
export interface PlanStep { key: string; module: string; identifier: string; source_id: string; source: string; depth: number; origin_path: string[]; priority: number; runnable: boolean; needs: string;
  reason: string; executable_now: boolean; endpoints: string[]; privacy: string }
export interface ExpansionPlan { policy: { max_depth: number; max_runs: number; max_per_pass: number; auto_passive: boolean }; steps: PlanStep[];
  seeds: { proposals: { label: string; state: string; action: string; reason: string; associated_id?: string }[]; skipped: Record<string, number> };
  budget: { used: number; max_runs: number; remaining: number; max_per_pass: number }; stop_reason: string; rules: string[]; history: { id: string; status: string; stop_reason: string; started: number; at: string }[] }
export const CLASS_BADGE: Record<EmailClass, string> = { confirmed: "healthy", likely: "medium", possible: "unknown", rejected: "failed" };
export const NEEDS_LABEL: Record<string, string> = { none: "ready", confirmation: "needs your confirmation", explicit_approval: "needs its own approval", blocked: "blocked", already_done: "already done", depth_limit: "beyond the depth limit" };
