// Types for the Master Profile API (Master Target Profile addendum). The server is the source of truth; these only describe its JSON.
export type MasterState = "unassessed" | "candidate" | "corroborated" | "conflicting" | "rejected" | "not_available" | "self_attested";
export interface MasterEvidence { id: string; title?: string; kind?: string; sha256?: string; url?: string | null }
export interface MasterItem { id: string; category: string; type: string; type_label: string; custom_type?: string; value: string; masked: boolean; restricted: boolean;
  normalized_value?: string; attributes?: Record<string, unknown>; source_id?: string; evidence: MasterEvidence[]; collection_method?: string; source_label?: string; origin: string; recorded_by?: string;
  observed_at?: string | null; last_verified_at?: string | null; confidence: string; verification_state: MasterState; state_label: string; self_attested?: boolean; sensitivity?: string;
  is_input: boolean; feeds_research: boolean; backed_by?: string; note?: string; discovered?: boolean; reference_only?: boolean; readonly?: boolean; open?: string; caveat: string;
  created_at?: string; asset_authorization?: { covered: boolean; reason: string } }
export interface MasterSection { key: string; title: string; items: MasterItem[]; counts: Record<MasterState, number>; types: string[]; empty_note: string }
export interface MasterType { type: string; category: string; label: string; restricted: boolean; reference_only: boolean; single_valued: boolean; feeds_research: boolean; backed_by: string }
export interface GapCategory { key: string; title: string; status: string; label: string; why: string; items: number; sources: { source: string; name: string; status: string; detail: string }[] }
export interface GapAction { priority: number; kind: string; text: string; go?: string; key?: string; category?: string }
export interface EmailFirst { has_email: boolean; message: string; configured?: number; attempted?: number; sources: { source_id: string; name: string; state: string; needs_key: string | null; sends: string; cost: string }[] }
export interface GapsT { categories: GapCategory[]; next_actions: GapAction[]; email_first: EmailFirst; coverage: { attempted_categories: number; of: number; label: string }; plan_stop_reason: string }
export interface MasterDoc { subject_id: string; role: string; sections: MasterSection[]; restricted_hidden: number; states: { key: MasterState; label: string }[]; notice: string; types: MasterType[];
  restricted_note: string; gaps: GapsT | null; duplicates: { type: string; ids: string[]; values: string[]; reason: string }[]; subject: { id: string; display_name: string } }
export interface BatchResult { created: number; existing: number; errors: { row: number; code: string; message: string }[] }
