// Types for the Active Intelligence & Verification API (addendum v1.1). The server is the source of truth; these only describe its JSON.
export interface AivTool { id: string; name: string; status: string; version: string | null; detail: string; role: string; license: string; install_hint: string; source_url: string }
export interface AivCaps { enabled: boolean; offline: boolean; classes: string[]; lab_class: string; asset_types: string[]; attestation_kinds: string[]; default_limits: Record<string, number>;
  forbidden: string[]; tools: AivTool[]; boundary: string }
export interface AssetAuth { id: string; asset_type: string; scope: string[]; ports: number[]; paths: string[]; allowed_classes: string[]; exclusions: string[]; limits: Record<string, number>;
  authorized_by: string; authority_role: string; source_of_authority: string; attestation_kind: string; starts_at: string; expires_at: string; revoked_at: string | null;
  state: string; state_reason: string; owner_subject_id: string | null; scope_snapshot_hash: string }
export interface PlanRow { index: number; kind: string; target: string; detail: Record<string, unknown>; allowed: boolean; code: string; reason: string; estimated_requests: number; impact: string }
export interface PlanPreview { ok: boolean; steps: PlanRow[]; problems: string[]; estimated_requests: number; limits: Record<string, number>; hosts: string[]; impact: string;
  tools: Record<string, string>; plan_hash: string; normalized_steps: Record<string, unknown>[]; disclosure: { external_services: string[]; data_retention: string; what_is_sent: string } }
export interface AivPlanT { id: string; asset_authorization_id: string; plan_hash: string; version: number; steps: Record<string, unknown>[]; limits: Record<string, unknown>; status: string;
  created_by: string; created_at: string; supersedes_id: string | null; target_profile_id: string | null }
export interface AivRunT { id: string; plan_id: string; status: string; started_at: string; finished_at: string | null; counts: Record<string, unknown>; abort_reason: string; tool_versions: Record<string, string> }
export interface AivObs { id: string; run_id: string; target_asset: string; check_type: string; finding_key: string; observed: Record<string, unknown>; severity: string; confidence: string;
  basis: string; remediation: string; evidence_id: string | null; observed_at: string; review_status: string; reviewer: string | null; review_note: string }
export interface TemplateApproval { id: string; template_id: string; sha256: string; semantics: { methods?: string[]; paths?: string[]; request_count?: number; name?: string; severity?: string }; reviewed_by: string; reviewed_at: string; revoked_at: string | null }
export interface BrandingT { active: { productName: string; shortName: string; tagline: string; edition: string; legacyNames: string[] }; preset: string; notice: string;
  presets: Record<string, { label: string; status: string; branding: { productName: string; shortName: string; tagline: string } }>; unchanged: string[] }
export interface ProfileVerification { enabled: boolean; subject_id: string; authorizations: AssetAuth[]; plans: AivPlanT[]; runs: AivRunT[]; observations: AivObs[];
  unlinked_case_authorizations: number; notice: string }

export const CLASS_LABEL: Record<string, string> = {
  http_metadata: "HTTP metadata (HEAD/GET, headers only)", tls_handshake: "TLS handshake (certificate and protocol)", tcp_connect: "TCP connect (open or closed, nothing sent)",
  service_detect: "Service detection (Nmap or Naabu, connect scan)", signature_check: "Signature check (approved read-only templates)", lab_network: "Private lab network (explicit owner statement)",
};
export const SEV_CLASS: Record<string, string> = { high: "failed", medium: "medium", low: "low", info: "unknown" };
