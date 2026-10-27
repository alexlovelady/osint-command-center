import { useState } from "react";
import { val } from "./ui";

const KIND: Record<string, string> = { github_commit_author: "GitHub commit author", github_profile_email: "GitHub profile lists this email", gravatar_profile: "Gravatar profile", openpgp_key: "Public PGP key",
  web_search_hit: "Web search result" };

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);

/** A finding's value as a short readable summary, with the stored record one click away. Nothing is removed: the raw value is shown under Raw evidence. */
export default function FindingValue({ value, predicate }: { value: unknown; predicate: string }) {
  const [raw, setRaw] = useState(false);
  const o = value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  let head = "";
  let sub = "";
  let link = "";
  const facts: string[] = [];
  if (o && predicate === "email.reference") {
    head = String(o.title ?? o.source ?? "Reference");
    sub = `${KIND[String(o.via_kind)] ?? String(o.via_kind ?? "reference").replace(/_/g, " ")} · ${String(o.source ?? "")} · matched ${String(o.match ?? "the address")}`;
    link = String(o.url ?? "");
    if (o.snippet) facts.push(clip(String(o.snippet), 140));
    const leads = (o.leads ?? {}) as Record<string, string[]>;
    for (const [k, v] of Object.entries(leads)) if (v.length) facts.push(`${k.replace(/_/g, " ")}: ${v.slice(0, 3).join(", ")}${v.length > 3 ? ` +${v.length - 3}` : ""}`);
  } else if (o) {
    const entries = Object.entries(o).filter(([, v]) => typeof v !== "object" || v === null);
    head = clip(entries.slice(0, 1).map(([k, v]) => `${k}: ${String(v)}`).join(""), 120);
    for (const [k, v] of entries.slice(1, 4)) facts.push(`${k}: ${clip(String(v), 80)}`);
    link = typeof o.url === "string" ? o.url : "";
  } else {
    head = clip(val(value), 200);
  }
  return (
    <div>
      <div><b>{head}</b></div>
      {sub && <div className="muted">{sub}</div>}
      {facts.map((f) => <div key={f} className="muted">{f}</div>)}
      {link.startsWith("http") && <div><a href={link} target="_blank" rel="noreferrer noopener">{clip(link.replace(/^https?:\/\//, ""), 70)}</a></div>}
      {o && <button onClick={() => setRaw(!raw)} aria-expanded={raw} style={{ marginTop: 4 }}>{raw ? "Hide raw evidence" : "Raw evidence"}</button>}
      {raw && <pre aria-label="Raw evidence" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", maxHeight: 240, overflow: "auto" }}>{JSON.stringify(value, null, 2)}</pre>}
    </div>
  );
}
