// Pure graph helpers shared by the canvas and its tests. The canvas is a VIEW of the workflow definition: positions are derived (never stored), so
// editing visually can never change what a workflow means. `toModel` -> `fromModel` returns the same definition.

export interface WfNode { id: string; type: string; depends_on: string[]; config: Record<string, unknown>; when?: { ref: string; op: string; value?: unknown } | null;
  run_on?: string; optional?: boolean; label?: string | null }
export interface WfDef { schema_version: 1; workflow_key: string; name: string; description?: string; owner_scope?: string; status?: string; tags?: string[];
  trigger: { type: string; schedule?: string | null; timezone?: string; enabled?: boolean; missed_run_policy?: string; event?: string | null };
  inputs: Record<string, string | number | boolean | null>; policy: Record<string, unknown>; nodes: WfNode[]; error_policy: Record<string, unknown> }

export interface Pos { x: number; y: number }
export const NODE_W = 168;
export const NODE_H = 54;
export const GAP_X = 48;
export const GAP_Y = 26;

/** Longest-path level per node; null when the graph has a cycle. */
export function levels(nodes: WfNode[]): Record<string, number> | null {
  const by = new Map(nodes.map((n) => [n.id, n]));
  const memo: Record<string, number> = {};
  const state: Record<string, number> = {};
  const visit = (id: string): boolean => {
    if (state[id] === 2) return true;
    if (state[id] === 1) return false;
    state[id] = 1;
    let best = 0;
    for (const d of by.get(id)?.depends_on ?? []) {
      if (!by.has(d)) continue;
      if (!visit(d)) return false;
      best = Math.max(best, memo[d]);
    }
    memo[id] = best + 1;
    state[id] = 2;
    return true;
  };
  for (const n of nodes) if (!visit(n.id)) return null;
  return memo;
}

/** Left-to-right layered layout. Deterministic: same definition, same picture. */
export function layout(nodes: WfNode[]): { pos: Record<string, Pos>; width: number; height: number } {
  const lv = levels(nodes) ?? Object.fromEntries(nodes.map((n, i) => [n.id, i + 1]));
  const cols: Record<number, string[]> = {};
  for (const n of nodes) (cols[lv[n.id]] ??= []).push(n.id);
  const pos: Record<string, Pos> = {};
  let h = 0;
  let maxCol = 0;
  for (const [c, ids] of Object.entries(cols)) {
    const col = Number(c);
    maxCol = Math.max(maxCol, col);
    ids.sort();
    ids.forEach((id, i) => { pos[id] = { x: (col - 1) * (NODE_W + GAP_X) + 16, y: i * (NODE_H + GAP_Y) + 16 }; });
    h = Math.max(h, ids.length * (NODE_H + GAP_Y));
  }
  return { pos, width: maxCol * (NODE_W + GAP_X) + 32, height: h + 32 };
}

export interface Edge { from: string; to: string }
export const edges = (nodes: WfNode[]): Edge[] => nodes.flatMap((n) => n.depends_on.map((d) => ({ from: d, to: n.id })));

export interface Model { meta: Omit<WfDef, "nodes">; nodes: WfNode[] }
export const toModel = (d: WfDef): Model => { const { nodes, ...meta } = structuredClone(d); return { meta, nodes }; };
export const fromModel = (m: Model): WfDef => ({ ...structuredClone(m.meta), nodes: structuredClone(m.nodes) }) as WfDef;

export function uniqueId(nodes: WfNode[], base: string): string {
  const ids = new Set(nodes.map((n) => n.id));
  if (!ids.has(base)) return base;
  for (let i = 2; i < 100; i++) if (!ids.has(`${base}_${i}`)) return `${base}_${i}`;
  return `${base}_x`;
}

export function removeNode(nodes: WfNode[], id: string): WfNode[] {
  return nodes.filter((n) => n.id !== id).map((n) => ({ ...n, depends_on: n.depends_on.filter((d) => d !== id) }));
}

/** Neighbour for arrow-key navigation: right = a node that depends on this one, left = a dependency, up/down = same column. */
export function neighbour(nodes: WfNode[], pos: Record<string, Pos>, id: string, dir: "left" | "right" | "up" | "down"): string | null {
  const me = nodes.find((n) => n.id === id);
  if (!me) return null;
  if (dir === "left") return me.depends_on[0] ?? null;
  if (dir === "right") return nodes.find((n) => n.depends_on.includes(id))?.id ?? null;
  const col = nodes.filter((n) => pos[n.id].x === pos[id].x).sort((a, b) => pos[a.id].y - pos[b.id].y);
  const i = col.findIndex((n) => n.id === id);
  return (dir === "up" ? col[i - 1] : col[i + 1])?.id ?? null;
}
