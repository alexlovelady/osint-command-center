// Theme preset "ops-hybrid" (alias blacksite-ghost): Blacksite Redline (amber/red urgency) + Ghost Grid (teal signal/grid).
// Colours live in theme.css as CSS variables; canvas-based views (Cytoscape, Leaflet) read them here so they follow the active scheme.
export const THEME_PRESET = "ops-hybrid";

export function cssVar(name: string, fallback = "#888888"): string {
  try {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
  } catch {
    return fallback;
  }
}

export const chart = () => ({
  primary: cssVar("--chart-1", "#d08a34"), tech: cssVar("--chart-2", "#4fa3a5"), alert: cssVar("--chart-3", "#c44b3c"),
  neutral: cssVar("--chart-4", "#8f9aa6"), ok: cssVar("--chart-5", "#5c9b7a"), edge: cssVar("--chart-edge", "#4d5a66"), label: cssVar("--chart-label", "#9aa4ae"),
});
