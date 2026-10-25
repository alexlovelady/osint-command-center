// Types for the DARKINT API (addendum v1.1 section 14). The server is the source of truth; these only describe its JSON.
export interface DarkSource { provider_id: string; name: string; state: "live" | "mocked" | "manual_only" | "disabled"; reason: string; verification: string; last_verified: string | null;
  licence: string; terms_url: string; authentication: string; scope_policy: string; source_type: string; cost_tier: string; quota: string; coverage_limitations: string; terms_note: string;
  enabled: boolean; automated: boolean; monitorable: boolean; identifier_kinds: string[]; credential_present: boolean | null; terms_acknowledged_at: string | null }
export type CovState = "unknown" | "not_checked" | "no_match_checked_sources" | "match_reported";
export interface CovProvider { provider_id: string; provider: string; state: CovState; checked_at: string | null; last_outcome: string | null; events: number }
export interface CovItem { identifier_id: string; kind: string; identifier: string; state: CovState; label: string; meaning: string; providers: CovProvider[]; checked_sources: { provider: string; checked_at: string }[] }
export interface DarkEvent { id: string; provider_id: string; provider: string; event_type: string; title: string; categories: string[]; first_seen: string | null; last_seen: string | null;
  claim_label: string; confidence: string; provider_ref: string; evidence_id: string | null; redacted: boolean; caveat: string }
export interface DarkGroup { group: string; sources: string[]; events: DarkEvent[]; first_seen: string | null; last_seen: string | null; categories: string[]; corroborated: boolean; review_status: string; note: string }
export interface DarkExposures { coverage: { items: CovItem[]; labels: Record<string, string>; notice: string }; groups: DarkGroup[];
  reviews: Record<string, { status: string; rationale: string; reviewer: string; at: string }[]>; actions: string[]; suggested: Record<string, string[]> }
export interface PreviewRow { identifier_id: string; kind: string; identifier: string; provider_id: string; provider: string; operation: string | null; allowed: boolean; code: string; reason: string;
  will_send: { to: string; data: string; credentials: string }; will_store: string; terms_url: string; cost: string; quota: string; terms_note: string; mocked: boolean }
export interface CheckResult { identifier_id: string; provider_id: string; outcome: string; code: string; detail: string; events: number }
export interface DarkMonitor { id: string; name: string; identifier_ids: string[]; providers: string[]; cadence_hours: number; expires_at: string; enabled: boolean; disabled_reason: string; last_run_at: string | null }
export interface DarkDashRow { case_id: string; case: string; subject_id: string; subject: string; mode: string; states: Record<CovState, number>; unreviewed_events: number; open_remediation: number;
  monitors_active: number; monitors_stopped: number; last_checked: string | null }
export const COV_CLASS: Record<CovState, string> = { match_reported: "failed", no_match_checked_sources: "healthy", unknown: "medium", not_checked: "unknown" };
export const COV_LABEL: Record<CovState, string> = { unknown: "Unknown", not_checked: "Not checked", no_match_checked_sources: "No match from checked sources", match_reported: "Match reported" };
