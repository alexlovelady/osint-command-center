import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Issue } from "../lib/automationsApi";
import { NODE_H, NODE_W, edges, layout, neighbour, type WfNode } from "../lib/workflowGraph";

interface Props {
  nodes: WfNode[];
  selected: string | null;
  onSelect: (id: string | null) => void;
  onDelete?: (id: string) => void;
  issues?: Issue[];
  warnings?: Issue[];
  states?: Record<string, string>;          // run overlay: node id -> state
  titles?: Record<string, string>;          // node type -> human title
  networkTypes?: Set<string>;
}

/** Visual node graph: pan (drag), zoom (wheel, +/- keys, buttons), minimap, keyboard navigation (arrows move between connected nodes, Enter selects, Delete removes).
 *  It only DRAWS the definition; positions are derived from it, so dragging the view can never change what a workflow does. */
export default function WorkflowCanvas({ nodes, selected, onSelect, onDelete, issues = [], warnings = [], states, titles = {}, networkTypes = new Set() }: Props) {
  const lay = useMemo(() => layout(nodes), [nodes]);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const drag = useRef<{ sx: number; sy: number; ox: number; oy: number } | null>(null);
  const box = useRef<HTMLDivElement | null>(null);
  const refs = useRef<Record<string, SVGGElement | null>>({});
  const [size, setSize] = useState({ w: 800, h: 420 });
  useEffect(() => {
    const el = box.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth || 800, h: el.clientHeight || 420 }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const zoom = useCallback((f: number) => setView((v) => ({ ...v, k: Math.min(2.5, Math.max(0.3, v.k * f)) })), []);
  const fit = useCallback(() => {
    const k = Math.min(1.2, Math.max(0.55, Math.min(size.w / lay.width, size.h / lay.height)));      // never so small the text is unreadable; pan or use the minimap
    setView({ x: lay.width * k > size.w ? 8 : (size.w - lay.width * k) / 2, y: 8, k });
  }, [lay, size]);
  useEffect(() => { fit(); }, [nodes.length, size.w]);   // eslint-disable-line react-hooks/exhaustive-deps

  const bad = useMemo(() => {
    const m: Record<string, { e: number; w: number }> = {};
    for (const i of issues) if (i.node) (m[i.node] ??= { e: 0, w: 0 }).e++;
    for (const i of warnings) if (i.node) (m[i.node] ??= { e: 0, w: 0 }).w++;
    return m;
  }, [issues, warnings]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "+" || e.key === "=") { zoom(1.2); return; }
    if (e.key === "-") { zoom(1 / 1.2); return; }
    if (e.key === "0") { fit(); return; }
    const t = e.target as Element;
    const id = t.getAttribute?.("data-node");
    if (!id) return;
    const dir = ({ ArrowLeft: "left", ArrowRight: "right", ArrowUp: "up", ArrowDown: "down" } as const)[e.key as "ArrowLeft"];
    if (dir) {
      e.preventDefault();
      const nx = neighbour(nodes, lay.pos, id, dir);
      if (nx) { onSelect(nx); refs.current[nx]?.focus(); }
    } else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(id); }
    else if ((e.key === "Delete" || e.key === "Backspace") && onDelete) { e.preventDefault(); onDelete(id); }
  };

  const mw = 150, mh = 84;
  const ms = Math.min(mw / lay.width, mh / lay.height);
  return (
    <div className="canvas-wrap">
      <div className="canvas-tools row" role="toolbar" aria-label="Canvas controls">
        <button onClick={() => zoom(1.2)} aria-label="Zoom in">+</button>
        <button onClick={() => zoom(1 / 1.2)} aria-label="Zoom out">−</button>
        <button onClick={fit} aria-label="Fit to screen">Fit</button>
        <span className="muted" style={{ fontSize: 12 }}>Drag to pan · wheel to zoom · arrows move between steps · Enter selects</span>
      </div>
      <div ref={box} className="canvas" tabIndex={0} role="application" aria-label={`Workflow canvas with ${nodes.length} steps. Use the arrow keys to move between steps.`}
        onKeyDown={onKey}
        onWheel={(e) => { e.preventDefault(); zoom(e.deltaY < 0 ? 1.1 : 1 / 1.1); }}
        onPointerDown={(e) => { if ((e.target as Element).closest("[data-node]")) return; drag.current = { sx: e.clientX, sy: e.clientY, ox: view.x, oy: view.y }; (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId); }}
        onPointerMove={(e) => { const d = drag.current; if (d) setView((v) => ({ ...v, x: d.ox + e.clientX - d.sx, y: d.oy + e.clientY - d.sy })); }}
        onPointerUp={() => { drag.current = null; }}
        onClick={(e) => { if (!(e.target as Element).closest("[data-node]")) onSelect(null); }}>
        <svg width="100%" height="100%" role="presentation">
          <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" className="cv-arrow" /></marker></defs>
          <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
            {edges(nodes).map((e, i) => {
              const a = lay.pos[e.from], b = lay.pos[e.to];
              if (!a || !b) return null;
              const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2, dx = Math.max(24, (x2 - x1) / 2);
              return <path key={i} className="cv-edge" markerEnd="url(#arrow)" d={`M${x1} ${y1} C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`} fill="none" />;
            })}
            {nodes.map((n) => {
              const p = lay.pos[n.id];
              const st = states?.[n.id];
              const b = bad[n.id];
              const net = networkTypes.has(n.type);
              const label = `${n.id}, ${titles[n.type] ?? n.type}${st ? `, ${st}` : ""}${b?.e ? `, ${b.e} problem${b.e > 1 ? "s" : ""}` : ""}${b?.w ? `, ${b.w} warning${b.w > 1 ? "s" : ""}` : ""}${n.optional ? ", optional" : ""}`;
              return (
                <g key={n.id} ref={(el) => { refs.current[n.id] = el; }} data-node={n.id} tabIndex={0} role="button" aria-label={label} aria-pressed={selected === n.id}
                  className={`cv-node${selected === n.id ? " sel" : ""}${net ? " net" : ""}${st ? ` st-${st}` : ""}${n.optional ? " opt" : ""}`} transform={`translate(${p.x} ${p.y})`}
                  onClick={(e) => { e.stopPropagation(); onSelect(n.id); }}>
                  <rect width={NODE_W} height={NODE_H} rx={4} />
                  <text x={10} y={22} className="cv-id">{n.id.length > 20 ? n.id.slice(0, 19) + "…" : n.id}</text>
                  <text x={10} y={40} className="cv-type">{(titles[n.type] ?? n.type).slice(0, 26)}{n.optional ? " · optional" : ""}</text>
                  {st && <text x={NODE_W - 8} y={40} textAnchor="end" className="cv-state">{st.replace(/_/g, " ")}</text>}
                  {b?.e ? <g aria-hidden><circle cx={NODE_W - 4} cy={4} r={8} className="cv-bad" /><text x={NODE_W - 4} y={8} textAnchor="middle" className="cv-badn">{b.e}</text></g> : null}
                  {!b?.e && b?.w ? <g aria-hidden><circle cx={NODE_W - 4} cy={4} r={8} className="cv-warn" /><text x={NODE_W - 4} y={8} textAnchor="middle" className="cv-badn">!</text></g> : null}
                </g>
              );
            })}
          </g>
        </svg>
        <svg className="minimap" width={mw} height={mh} role="img" aria-label="Minimap"
          onClick={(e) => { const r = e.currentTarget.getBoundingClientRect(); const x = (e.clientX - r.left) / ms, y = (e.clientY - r.top) / ms; setView((v) => ({ ...v, x: size.w / 2 - x * v.k, y: size.h / 2 - y * v.k })); }}>
          <rect width={mw} height={mh} className="mm-bg" />
          {nodes.map((n) => <rect key={n.id} x={lay.pos[n.id].x * ms} y={lay.pos[n.id].y * ms} width={NODE_W * ms} height={NODE_H * ms} className={`mm-node${selected === n.id ? " sel" : ""}`} />)}
          <rect className="mm-view" x={(-view.x / view.k) * ms} y={(-view.y / view.k) * ms} width={(size.w / view.k) * ms} height={(size.h / view.k) * ms} />
        </svg>
      </div>
    </div>
  );
}
