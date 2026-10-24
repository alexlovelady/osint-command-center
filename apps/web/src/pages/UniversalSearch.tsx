import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import SearchComposer from "../components/SearchComposer";
import { Empty, ErrorBox, Loading } from "../components/ui";
import { api, type CaseT } from "../lib/api";

export default function UniversalSearch({ onClose, open }: { onClose: () => void; open: (caseId: string) => void }) {
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api<{ items: CaseT[] }>("/cases?status=open") });
  const [caseId, setCaseId] = useState("");
  const chosen = caseId || cases.data?.items[0]?.id || "";
  return (
    <div className="modal-bg" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Universal search">
        <div className="row"><b style={{ flex: 1 }}>Universal search</b><button onClick={onClose} aria-label="Close">Esc</button></div>
        {cases.isLoading && <Loading what="cases" />}
        {cases.isError && <ErrorBox error={cases.error} />}
        {cases.data && cases.data.items.length === 0 && <Empty title="No open case" hint="Searches run inside a case so results keep their provenance. Create one under Cases." />}
        {chosen && (
          <>
            <label className="muted">Case
              <select value={chosen} onChange={(e) => setCaseId(e.target.value)}>
                {cases.data?.items.map((c) => <option key={c.id} value={c.id}>{c.title}</option>)}
              </select>
            </label>
            <SearchComposer key={chosen} caseId={chosen} />
            <button onClick={() => open(chosen)} style={{ marginTop: 8 }}>Open case</button>
          </>
        )}
      </div>
    </div>
  );
}
