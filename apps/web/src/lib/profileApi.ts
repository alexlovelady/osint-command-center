// Types for the Target Profile API (addendum TP-1.0). Server is the source of truth; these only describe its JSON.
export interface EvidenceRef { id: string; title: string; kind: string; sha256: string; url: string | null; retrieved_at: string }
export interface SubjectT { id: string; case_id: string; type: string; display_name: string; mode: "self" | "client" | "organization"; purpose: string;
  status: string; owner: string | null; sensitivity: string; retention_days: number | null }
export interface IdentT { id: string; kind: string; value: string; masked: boolean; status: string }
export interface ClaimT { id: string; field: string; value: Record<string, unknown>; state: string; state_label: string; evidence: EvidenceRef[];
  reviewer?: string | null; reason?: string; from?: string }
export interface SectionT { key: string; title: string; identifiers: IdentT[]; claims: ClaimT[]; state_note: string }
export interface AuthT { status: string; mode: string; consent_id: string | null; expires_at: string | null; source_classes: string[]; message: string;
  verification_method?: string; verifier?: string; has_proof?: boolean; receipt: { id: string; obtained_at: string } | null }
export interface CandidateT { id: string; canonical_url: string; site: string; hypothesis: string; adapters: string[]; independent_signals: number;
  state: string; reviewed_by: string | null; reviewed_at: string | null; review_basis: string; first_seen_at: string; last_seen_at: string;
  observation_count: number; evidence: EvidenceRef[]; note: string }
export interface ExposureT { id: string; class: string; provider: string; status: string; risk: string; descriptor: string; last_checked: string; remediation_state: string }
export interface RemediationT { id: string; issue: string; priority: string; state: string; due_at: string | null; guidance: string }
export interface ProfileT { subject: SubjectT; case: { id: string; title: string; category: string }; authorization: AuthT; sections: SectionT[];
  identifiers: IdentT[]; unresolved_leads: CandidateT[]; image_matches: { total: number; unreviewed: number }; exposure: ExposureT[];
  remediation: RemediationT[]; risk_summary: { confirmed_exposures: number; highest_risk: string; not_assessed: number }; role: string;
  counts: { identifiers: number; claims: number; candidates: number; verified: number }; notice: string; next_action?: string; last_collected?: string | null }
export interface HistoryT { id: string; target_type: string; target_id: string; from: string; to: string; reviewer: string; basis: string; bulk_id: string | null; reverts: string | null; at: string }

export const STATE_CLASS: Record<string, string> = {
  verified: "st-ok", subject_confirmed: "st-ok", confirmed: "st-ok", candidate: "st-warn", unsure: "st-warn", conflicting: "st-bad", rejected: "st-bad", not_assessed: "st-mute",
  completed: "st-ok", partial: "st-warn", outdated: "st-warn", running: "st-warn", approved: "st-warn", not_run: "st-mute", failed: "st-bad", blocked: "st-bad",
  cancelled: "st-mute", unsupported: "st-mute", unavailable: "st-bad", planned: "st-mute",
};
export interface CoverageCell { source_id: string; name: string; maturity: string; status: string; detail: string; last_success: string | null }
export interface CoverageT { categories: { key: string; title: string; cells: CoverageCell[] }[]; totals: Record<string, number>; approved_tasks: number; completed_tasks: number;
  label: string; next_action: string; last_collected: string | null }
export interface ResearchEntry { key: string; identifier_id: string; identifier_kind: string; identifier: string; source_id: string; name: string; category: string;
  consent_class: string; privacy: string; maturity: string; legal_note: string; commercial_use: string; runnable: boolean; reason: string; requires_confirmation: boolean;
  warnings: string[]; endpoints: string[]; rate_limit_per_minute: number | null; cost: string; needs_key: string | null; health?: string;
  previous: { status: string; last_success: string | null; result_count: number; limitations: string } | null }
export interface ResearchPlanT { subject_id: string; entries: ResearchEntry[]; budget: { max_per_approval: number; runnable: number; paid_requests: number }; stop_rules: string[]; note: string; offline: boolean }
export interface TaskT { id: string; category: string; source_id: string; status: string; run_id: string | null; last_attempt: string | null; last_success: string | null; result_count: number; limitations: string }
export interface TemplateT { slug: string; key: string; name: string; description: string; maturity: string; capability_gaps: string[]; dependencies: string[]; optional_dependencies: string[];
  trigger: string; quota_note: string; availability?: { state: string; missing: { adapter: string; status: string; setup: string }[]; gaps: string[] } }
export const SOURCE_CLASSES: [string, string][] = [
  ["public_passive", "Public passive sources (DNS, registries, archives)"], ["public_site_query", "Username checks on public sites (Sherlock/Maigret)"],
  ["documents", "Published documents"], ["image_analysis", "Image analysis"], ["reverse_image", "Reverse-image search (manual)"],
  ["exposure_check", "Exposure / breach checks (owner-verified)"], ["professional_history", "Professional history"],
];
