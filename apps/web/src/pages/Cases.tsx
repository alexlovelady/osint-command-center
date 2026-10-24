import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, ErrorBox, Loading, fmt } from "../components/ui";
import { api, type CaseT } from "../lib/api";

const CATS = ["cyber", "business", "geospatial", "media", "people", "threat"];

export default function Cases({ open }: { open: (id: string) => void }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["cases"], queryFn: () => api<{ items: CaseT[]; total: number }>("/cases") });
  const [form, setForm] = useState({ title: "", category: "cyber", purpose: "" });
  const create = useMutation({
    mutationFn: () => api<CaseT>("/cases", { method: "POST", json: form }),
    onSuccess: (c) => { qc.invalidateQueries({ queryKey: ["cases"] }); open(c.id); },
  });
  return (
    <>
      <h2>Cases</h2>
      <form className="card row" onSubmit={(e) => { e.preventDefault(); create.mutate(); }} aria-label="New case">
        <input data-tour="case-title" aria-label="Case title" placeholder="Case title" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} style={{ flex: 2, minWidth: 200 }} />
        <select data-tour="case-category" aria-label="Category" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} style={{ width: 140 }}>
          {CATS.map((c) => <option key={c}>{c}</option>)}
        </select>
        <input data-tour="case-purpose" aria-label="Purpose" placeholder={form.category === "people" ? "Purpose (required for people cases)" : "Purpose / scope (recommended)"} value={form.purpose} onChange={(e) => setForm({ ...form, purpose: e.target.value })} style={{ flex: 3, minWidth: 220 }} />
        <button data-tour="case-create" className="primary" disabled={!form.title.trim() || create.isPending}>Create case</button>
      </form>
      {create.isError && <ErrorBox error={create.error} />}
      {q.isLoading && <Loading what="cases" />}
      {q.isError && <ErrorBox error={q.error} />}
      {q.data && q.data.items.length === 0 && <Empty title="No cases" hint="Create your first case above." />}
      {q.data && q.data.items.length > 0 && (
        <table style={{ marginTop: 14 }}>
          <thead><tr><th>Title</th><th>Category</th><th>Status</th><th>Findings</th><th>Updated</th></tr></thead>
          <tbody>
            {q.data.items.map((c) => (
              <tr key={c.id}>
                <td><a href={`#/case/${c.id}`}>{c.title}</a></td><td>{c.category}</td><td><Badge v={c.status} /></td>
                <td>{c.finding_count ?? 0}</td><td>{fmt(c.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
