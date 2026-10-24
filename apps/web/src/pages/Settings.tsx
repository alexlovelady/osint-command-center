import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading } from "../components/ui";
import { api, getToken, setToken } from "../lib/api";
import AdminPanel from "./AdminPanel";

interface S { offline: boolean; max_concurrency: number; data_dir: string }

export default function Settings() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["settings"], queryFn: () => api<S>("/settings") });
  const put = useMutation({ mutationFn: (values: Record<string, unknown>) => api<S>("/settings", { method: "PUT", json: { values } }),
    onSuccess: () => qc.invalidateQueries() });
  const [tok, setTok] = useState("");
  return (
    <>
      <h2>Settings</h2>
      {q.isLoading && <Loading what="settings" />}
      {q.isError && <ErrorBox error={q.error} />}
      {q.data && (
        <div className="card">
          <label className="row"><input type="checkbox" style={{ width: "auto" }} checked={q.data.offline} onChange={(e) => put.mutate({ offline: e.target.checked })} />
            Offline mode (pause every network source; saved cases stay readable)</label>
          <p className="muted">Data directory: <code>{q.data.data_dir}</code></p>
          <p className="muted">API secrets are stored only in the OS credential vault (never in this database or in logs).</p>
        </div>
      )}
      <AdminPanel />
      <h3>Session</h3>
      <div className="card row">
        <input type="password" aria-label="Session token" placeholder={getToken() ? "token set for this tab" : "paste session token"} value={tok} onChange={(e) => setTok(e.target.value)} style={{ maxWidth: 360 }} />
        <button onClick={() => { setToken(tok); setTok(""); qc.invalidateQueries(); }} disabled={!tok}>Use token</button>
      </div>
    </>
  );
}
