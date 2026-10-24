import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ErrorBox } from "./components/ui";
import CopilotPanel from "./components/CopilotPanel";
import { api, getToken } from "./lib/api";
import { setAppCtx } from "./lib/appContext";
import CaseView from "./pages/CaseView";
import Cases from "./pages/Cases";
import Overview from "./pages/Overview";
import Settings from "./pages/Settings";
import Setup from "./pages/Setup";
import Tools from "./pages/Tools";
import UniversalSearch from "./pages/UniversalSearch";

function useRoute(): [string, (r: string) => void] {
  const [r, setR] = useState(() => window.location.hash.replace(/^#\/?/, "").split("&")[0] || "overview");
  useEffect(() => {
    const on = () => {
      getToken(); // a #token=… fragment set after load is captured and scrubbed, not treated as a route
      setR(window.location.hash.replace(/^#\/?/, "").split("&")[0] || "overview");
    };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return [r, (x) => { window.location.hash = `/${x}`; }];
}

const NAV: [string, string][] = [["overview", "Overview"], ["cases", "Cases"], ["tools", "Tool Manager"], ["setup", "Setup"], ["settings", "Settings"]];

export default function App() {
  getToken(); // capture + scrub #token=… before routing reads the hash
  const [route, go] = useRoute();
  const [search, setSearch] = useState(false);
  const [copilot, setCopilot] = useState(() => { try { return localStorage.getItem("osintcc.copilot.open") === "1"; } catch { return false; } });
  const toggleCopilot = (v: boolean) => { setCopilot(v); try { localStorage.setItem("osintcc.copilot.open", v ? "1" : "0"); } catch { /* the panel still works without storage */ } };
  const setup = useQuery({ queryKey: ["setup-banner"], queryFn: () => api<{ completed: boolean }>("/setup/status"), retry: false });
  useEffect(() => {  // first run: land on Setup once, unless the user already navigated somewhere
    if (setup.data && !setup.data.completed && !window.location.hash.replace(/^#\/?/, "")) go("setup");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [setup.data]);
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setSearch(true); }
      if (e.key === "Escape") setSearch(false);
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);
  const [section, id] = route.split("/");
  useEffect(() => {  // the Copilot reads where the user is from here
    const r = section === "case" && id ? "case" : section;
    setAppCtx({ route: r, case_id: r === "case" ? id : null, tool_id: null, ...(r === "case" ? {} : { tab: null }) });
  }, [section, id]);
  let page;
  if (section === "case" && id) page = <CaseView id={id} />;
  else if (section === "cases") page = <Cases open={(i) => go(`case/${i}`)} />;
  else if (section === "tools") page = <Tools />;
  else if (section === "settings") page = <Settings />;
  else if (section === "setup") page = <Setup />;
  else if (section === "overview") page = <Overview go={go} />;
  else page = <ErrorBox error={new Error("Page not found")} />;
  return (
    <div className="app">
      <nav className="side" aria-label="Primary">
        <h1>OSINT Command Center</h1>
        {NAV.map(([k, label]) => (
          <a key={k} href={`#/${k}`} data-tour={`nav-${k}`} aria-current={section === k || (k === "cases" && section === "case") ? "page" : undefined}>{label}</a>
        ))}
        <p className="muted" style={{ margin: "18px 8px", fontSize: 12 }}>
          Public-source, lawful research only. Results are leads with cited evidence, not conclusions.
        </p>
      </nav>
      <div>
        <header className="top">
          <button onClick={() => setSearch(true)} aria-label="Open universal search (Ctrl+K)">Universal search <kbd>Ctrl+K</kbd></button>
          <button onClick={() => toggleCopilot(!copilot)} aria-pressed={copilot} aria-label="Toggle the AI Copilot">Copilot</button>
          <span className="grow" />
          <span className="muted">{navigator.onLine ? "network: available" : "offline"}</span>
        </header>
        {setup.data && !setup.data.completed && section !== "setup" && (
          <div className="banner" role="region" aria-label="First-run setup" style={{ margin: "8px 20px" }}>
            Setup is not finished: optional tools and a local AI model have not been installed. <a href="#/setup">Open Setup</a>
          </div>)}
        <main>{page}</main>
      </div>
      <CopilotPanel open={copilot} setOpen={toggleCopilot} />
      {search && <UniversalSearch onClose={() => setSearch(false)} open={(c) => { setSearch(false); go(`case/${c}`); }} />}
    </div>
  );
}
