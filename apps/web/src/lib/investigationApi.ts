// Types for the one-click investigation API. The server is the source of truth; these only describe its JSON.
export type RunStatus = "draft" | "queued" | "collecting" | "correlating" | "expanding" | "awaiting_review" | "waiting_limits" | "complete_with_limits" | "completed" | "paused" | "cancelled" | "failed";
export const ACTIVE_STATUSES: RunStatus[] = ["queued", "collecting", "correlating", "expanding"];
/** Parked, not finished: every remaining check is waiting for a provider limit to reset. A durable resumer continues it. */
export const WAITING_STATUSES: RunStatus[] = ["waiting_limits"];
export const STATUS_TEXT: Record<RunStatus, string> = {
  draft: "Needs authorization", queued: "Queued", collecting: "Collecting", correlating: "Connecting results", expanding: "Following leads", awaiting_review: "Needs your decision", waiting_limits: "Waiting for provider limits",
  complete_with_limits: "Complete, with limits", completed: "Complete", paused: "Paused", cancelled: "Stopped", failed: "Stopped on an error",
};
export const STATUS_BADGE: Record<RunStatus, string> = {
  draft: "st-warn", queued: "st-warn", collecting: "st-warn", correlating: "st-warn", expanding: "st-warn", awaiting_review: "st-warn", waiting_limits: "st-warn", complete_with_limits: "st-ok", completed: "st-ok",
  paused: "st-mute", cancelled: "st-mute", failed: "st-bad",
};
export const STOP_TEXT: Record<string, string> = {
  needs_approval: "Waiting for your approval of the providers listed below.", decisions: "Waiting for your decisions on the leads in Review.", needs_key: "Some sources need an API key.",
  budget_exhausted: "Stopped at the source-call budget.", max_depth: "Stopped at the depth limit.", runtime_cap: "Stopped at the runtime limit.", authorization: "The authorization ended.",
  offline: "Offline mode is on.", case_not_open: "The case is not open.", no_new_leads: "No new leads remain.", coverage_gaps: "Some methods are unavailable (see Coverage).",
  cancelled: "Stopped by you.", provider_limits: "Every remaining check is waiting for a provider’s limit to reset. They continue by themselves.",
  work_cancelled: "Some queued checks were cancelled, so they did not run. Use Refresh results to run them.",
  provider_blocked: "A provider refused (key rejected, plan restriction or switched off). See what could not be done.", source_errors: "Some sources had errors or timed out. See what could not be done.", stalled: "Stopped waiting for a check that did not finish. Use Check for more to continue.", internal_error: "Stopped on an internal error.", step_refused: "A step was refused by the safety checks.",
};

export interface ManifestRow { key: string; source_id: string; source: string; module: string; identifier_id: string; identifier_kind: string; identifier: string; status: string; status_label: string;
  reason: string; third_party: boolean; recipients: string[]; maturity: string; verified_live: boolean; category: string; data_classes: string[]; depth: number }
export interface Manifest { rows: ManifestRow[]; counts: Record<string, number>; third_parties: string[]; authorization: { status: string; message?: string }; stop_reason: string; approvable: string[] }
export interface PrepareOut { case_id: string; subject_id: string; added: { kind: string; id: string }[]; skipped: { kind: string; code: string; message: string }[]; manifest: Manifest; run: { id: string; status: RunStatus } | null }
export interface Units { done: number; running: number; failed: number; waiting_approval: number; not_run: number; no_match?: number; unavailable?: number; queued?: number; waiting_limits?: number; blocked?: number; remaining?: number }
export interface RunRow { id: string; case_id: string; subject_id: string; name: string; kind: string; status: RunStatus; stop_reason: string; updated_at: string; created_at: string; units: Units; pending_decisions: number }
export interface Progress { id: string; status: RunStatus; phase: string; pass: number; stop_reason: string; updated_at: string; started_at: string | null; finished_at: string | null; units: Units; label: string;
  pending_decisions: number; policy: Record<string, number>; last_error: string; next_eligible_at?: string | null; subject_id?: string; case_id?: string; kind?: string; approved_sources?: string[]; excluded_sources?: string[] }
export interface FactRow { category: string; type: string; value: string; state: string; state_label: string; evidence: number }
export interface InboxItem { id: string; kind: "account" | "email" | "item" | "seed"; title: string; detail: string; claim: string; signals: number; tools: string[]; evidence: number; state: string; note: string }
export interface Inbox { items: InboxItem[]; total: number; by_kind: Record<string, number> }
export interface AccountingSource { source_id: string; source: string; status: string; runs: number; retrieved: number; findings: number; evidence: number; candidate_accounts: number; profile_items: number;
  shared_with_other_tools: number; explain: string; limitations: string }
export interface Accounting { sources: AccountingSource[]; accounts: { tool_hits: number; unique_accounts: number; seen_by_more_than_one_tool: number; by_review_state: Record<string, number>;
  confirmed_by: Record<string, number>; explain: string }; profile_items: { discovered: number; by_type: Record<string, number> } }
export interface Limit { code: string; source: string; input: string; text: string }
export interface CoverageCell { source_id: string; name: string; maturity: string; status: string; detail: string; last_success: string | null }
export interface Summary { run: { id: string; status: RunStatus; kind: string; policy: Record<string, number>; approved_sources: string[]; excluded_sources: string[]; stop_reason: string; created_at: string; requested_by: string };
  subject: { id: string; case_id: string; display_name: string; type: string; mode: string; purpose: string }; authorization: { status: string; message?: string; expires_at?: string | null };
  progress: Progress; facts: Record<string, FactRow[]>; fact_counts: Record<string, number>; possible_associations: number; coverage: { key: string; title: string; cells: CoverageCell[] }[];
  accounting: Accounting; decisions: { open: number; top: InboxItem[] }; limits: Limit[]; next_actions: { text: string; go?: string; kind: string }[];
  email_first: { has_email: boolean; message: string }; manifest: { counts: Record<string, number>; rows: ManifestRow[]; third_parties: string[] }; invite: string }
export interface RunEvent { seq: number; kind: string; message: string; detail: Record<string, unknown>; at: string }
export interface DecideOut { preview: boolean; applied?: number; bulk_id?: string; counts: Record<string, number>; total: number; sites: string[]; exceptions: { id: string; reason: string }[]; effect: string; undo?: string }
export interface Candidate { id: string; canonical_url: string; site: string; hypothesis: string; adapters: string[]; independent_signals: number; state: string; ownership: string; observation_count: number;
  evidence: { id: string; title: string; kind: string; sha256: string; url: string | null }[]; first_seen_at: string; last_seen_at: string }
export const INPUT_KINDS: [string, string][] = [["name", "Name"], ["email", "Email"], ["phone", "Phone"], ["username", "Username"], ["alias", "Alias"], ["url", "Website or profile URL"], ["domain", "Owned domain"], ["organization", "Organization"]];
export const kindLabel = (k: string) => INPUT_KINDS.find((x) => x[0] === k)?.[1] ?? k;
