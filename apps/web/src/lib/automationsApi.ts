import type { WfDef } from "./workflowGraph";

export interface Issue { code: string; node: string | null; message: string }
export interface Validation { valid: boolean; errors: Issue[]; warnings: Issue[]; nodes: Record<string, { type: string; title: string; risk: string; side_effects: string; network: boolean }>;
  permissions: { network: boolean; network_mode: string; adapters: string[]; writes_local: boolean; external: boolean; active: boolean }; estimated_requests: Record<string, number>;
  explanation?: Explanation | null }
export interface Availability { state: "ready" | "partial" | "setup_required"; missing: { adapter: string; status: string; setup: string }[]; optional_missing: string[]; gaps: string[] }
export interface TemplateT { slug: string; key: string; category: string; name: string; description: string; catalog_trigger: string; trigger: string; tags: string[];
  dependencies: string[]; optional_dependencies: string[]; quota_note: string; maturity: string; capability_gaps: string[]; availability: Availability; checksum: string;
  inputs?: { name: string; label: string; type: string; required: boolean; example: string | null }[]; legal_notes?: string; example_output?: string; instructions?: string; definition?: WfDef }
export interface WorkflowT { id: string; name: string; case_id: string | null; state: string; rev: number; template_slug: string | null; latest_revision: number | null;
  active_version_id: string | null; published: boolean; unpublished_changes: boolean; trigger: WfDef["trigger"]; updated_at: string; definition?: WfDef;
  versions?: { id: string; revision: number; hash: string; published_at: string; created_by: string }[] }
export interface Explanation { name: string; runs: string; starts_disabled: boolean; network_mode: string; limits: Record<string, number>; note: string;
  steps: { id: string; type: string; title: string; what: string; after: string[]; risk: string; side_effects: string; contacts: string[]; optional: boolean }[];
  permissions: Validation["permissions"]; validation: { valid: boolean; errors: Issue[]; warnings: Issue[] } }
export interface RunT { id: string; workflow_id: string; workflow_name: string | null; template_slug: string | null; case_id: string | null; revision: number | null; state: string;
  trigger_type: string; dry_run: boolean; simulated: boolean; queued_at: string; started_at: string | null; ended_at: string | null; error_code: string | null; evidence_count: number;
  created_by: string; summary: { nodes?: Record<string, string>; warnings?: string[]; failures?: { node: string; code: string; message: string }[]; requests?: Record<string, number> } }
export interface NodeRunT { node: string; attempt: number; state: string; started_at: string; ended_at: string | null; duration_ms: number | null; input_digest: string | null;
  error_code: string | null; output: Record<string, unknown> | null; diagnostics: Record<string, unknown> }
export interface RunDetail extends RunT { nodes: NodeRunT[]; version: { id: string; revision: number; hash: string } | null; source_urls: string[]; environment: Record<string, string>;
  inputs: Record<string, unknown>; label: string | null }
export interface NoteT { id: string; workflow_id: string | null; run_id: string | null; severity: string; status: string; title: string; body: string; count: number; created_at: string;
  acknowledged_at: string | null; details: Record<string, unknown> }
export interface ApprovalT { id: string; workflow_id: string; version_id: string; kind: "activation" | "collection"; status: string; scope: { adapters: string[]; network_mode: string;
  needs_confirmation: string[]; risk: string; trigger: { type: string; schedule?: string; timezone?: string } }; requested_at: string; expires_at: string | null; authorization_id: string | null }
export interface SuggestionT { id: string; case_id: string | null; template: string; category: string; rationale: string; basis: Record<string, unknown> }
export interface NodeTypeT { type: string; title: string; description: string; produces: string; side_effects: string; risk: string; network: boolean;
  fields: { name: string; kind: string; options?: string[]; min?: number; max?: number }[]; ref_types: Record<string, string[]> }
export interface ProposeResult { draft: WfDef | null; source: string; template_slug: string | null; valid: boolean; validation?: { errors: Issue[]; warnings: Issue[]; permissions: Validation["permissions"] };
  explanation?: Explanation | null; assumptions: string[]; questions: string[]; attempts: { attempt: number; problem: string }[]; model: { used: boolean; reason: string; profile?: string | null };
  message?: string; note?: string }
export interface DiagnoseResult { problems: { node: string; attempt: number; code: string; message: string | null; fix: string }[]; proposals: { op: string; node: string; from?: string; to?: string; why: string }[];
  healthy_run: boolean; note: string }
export interface AutoSettings { timezone: string; max_concurrent_runs: number; notifications: { dedupe_window_hours: number; quiet_hours: { enabled: boolean; start: string; end: string; timezone: string };
  digest: { enabled: boolean; time: string }; webhooks: Record<string, string> }; suggestions: { enabled: boolean; disabled_categories: string[]; include_sensitive: boolean };
  cloud_ai_opt_in: string[]; email: { available: boolean; note: string } }

export const AVAIL_LABEL: Record<string, string> = { ready: "ready", partial: "partial", setup_required: "setup required" };
export const MATURITY_LABEL: Record<string, string> = { definition: "definition only", fixture_tested: "fixture-tested", runtime_tested: "runtime-tested", real_adapter_tested: "live-tested" };
export const RUN_STATES = ["queued", "waiting_for_approval", "running", "paused", "retrying", "failed", "cancelled", "completed", "completed_with_warnings"];
