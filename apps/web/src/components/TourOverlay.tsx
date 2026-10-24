import { useEffect, useState } from "react";
import { navigateTo } from "../lib/appContext";

export interface TourStep { n: number; go: { route: string; tab?: string }; target?: string | null; text: string }

const esc = (v: string): string => (typeof CSS !== "undefined" && CSS.escape ? CSS.escape(v) : v.split('"').join(""));

type Rect = { top: number; left: number; width: number; height: number };

/** Highlights real UI elements (marked with data-tour="…") one step at a time. If an element is not on screen it says so instead of guessing. */
export default function TourOverlay({ title, steps, onClose }: { title: string; steps: TourStep[]; onClose: () => void }) {
  const [i, setI] = useState(0);
  const [rect, setRect] = useState<Rect | null>(null);
  const [missing, setMissing] = useState(false);
  const step = steps[i];

  useEffect(() => {
    if (!step) return;
    setRect(null);
    setMissing(false);
    navigateTo({ route: step.go.route, tab: step.go.tab ?? null });
    let tries = 0;
    let found = false;
    const find = () => step.target ? document.querySelector<HTMLElement>(`[data-tour="${esc(step.target)}"]`) : null;
    const measure = () => {
      const el = find();
      if (!el) {
        if (!found && ++tries > 16) setMissing(true);
        return;
      }
      if (!found) { found = true; el.scrollIntoView?.({ block: "center", behavior: "smooth" }); }
      const r = el.getBoundingClientRect();
      setMissing(false);
      setRect({ top: r.top, left: r.left, width: r.width, height: r.height });
    };
    const t = window.setInterval(measure, 250);
    measure();
    window.addEventListener("resize", measure);
    return () => { window.clearInterval(t); window.removeEventListener("resize", measure); };
  }, [step]);

  useEffect(() => {
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);

  if (!step) return null;
  const pad = 6;
  const tipTop = rect ? Math.min(window.innerHeight - 190, rect.top + rect.height + 14) : undefined;
  const tipLeft = rect ? Math.max(12, Math.min(window.innerWidth - 372, rect.left)) : undefined;
  return (
    <div className="tour" role="dialog" aria-label={`Guided tutorial: ${title}`}>
      {rect && <div className="tour-hole" style={{ top: rect.top - pad, left: rect.left - pad, width: rect.width + pad * 2, height: rect.height + pad * 2 }} />}
      <div className="tour-tip card" style={rect ? { top: tipTop, left: tipLeft } : { bottom: 24, left: "50%", transform: "translateX(-50%)" }}>
        <div className="muted" style={{ fontSize: 12 }}>{title} · step {i + 1} of {steps.length}</div>
        <p style={{ margin: "6px 0 10px" }}>{step.text}</p>
        {missing && <p className="muted" style={{ marginTop: 0 }}>I can't find that control on this screen right now (it may be hidden, or this view is different). Follow the text above; nothing is guessed.</p>}
        <div className="row">
          <button onClick={() => setI(Math.max(0, i - 1))} disabled={i === 0}>Back</button>
          {i < steps.length - 1
            ? <button className="primary" onClick={() => setI(i + 1)}>Next</button>
            : <button className="primary" onClick={onClose}>Done</button>}
          <span className="grow" />
          <button onClick={onClose} aria-label="Close tutorial">Close</button>
        </div>
      </div>
    </div>
  );
}
