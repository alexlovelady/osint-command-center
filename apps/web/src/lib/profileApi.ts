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
};
export const SOURCE_CLASSES: [string, string][] = [
  ["public_passive", "Public passive sources (DNS, registries, archives)"], ["public_site_query", "Username checks on public sites (Sherlock/Maigret)"],
  ["documents", "Published documents"], ["image_analysis", "Image analysis"], ["reverse_image", "Reverse-image search (manual)"],
  ["exposure_check", "Exposure / breach checks (owner-verified)"], ["professional_history", "Professional history"],
];
