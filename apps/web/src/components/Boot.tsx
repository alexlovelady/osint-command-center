import { useEffect, useState, type ReactNode } from "react";
import { connectDesktopBackend, inDesktopShell } from "../lib/api";

/** In the desktop shell, blocks on backend readiness with a diagnostic + retry experience (spec 3.1). */
export default function Boot({ children }: { children: ReactNode }) {
  const [state, setState] = useState<"starting" | "ready" | "failed">(inDesktopShell() ? "starting" : "ready");
  const [detail, setDetail] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!inDesktopShell()) return;
    let stop = false;
    setState("starting");
    (async () => {
      for (let i = 0; i < 120 && !stop; i++) {
        try {
          await connectDesktopBackend();
          if (!stop) setState("ready");
          return;
        } catch (e) {
          const msg = String(e);
          if (!msg.includes("starting")) { setDetail(msg.replace(/^failed: /, "")); setState("failed"); return; }
          await new Promise((r) => setTimeout(r, 500));
        }
      }
      if (!stop) { setDetail("The backend did not become ready within 60 seconds."); setState("failed"); }
    })();
    return () => { stop = true; };
  }, [attempt]);
  if (state === "ready") return <>{children}</>;
  return (
    <main style={{ maxWidth: 560, margin: "18vh auto", padding: 20 }} role="status" aria-live="polite">
      <h2>OSINT Command Center</h2>
      {state === "starting" && <p className="muted">Starting the local backend…</p>}
      {state === "failed" && (
        <>
          <div className="banner err" role="alert">{detail}</div>
          <p className="muted">Nothing was sent anywhere. Check the Python environment (<code>uv sync</code>) and retry.</p>
          <button className="primary" onClick={() => setAttempt((a) => a + 1)}>Retry</button>
        </>
      )}
    </main>
  );
}
