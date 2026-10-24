// Simple line icons for the sidebar (decorative: the link text carries the meaning).
const P: Record<string, string> = {
  overview: "M3 12l9-8 9 8M5 10v10h5v-6h4v6h5V10",
  cases: "M3 7h6l2 2h10v10H3z",
  tools: "M14 6a4 4 0 0 0-5 5L3 17l4 4 6-6a4 4 0 0 0 5-5l-3 3-3-1-1-3z",
  setup: "M4 6h16M4 12h16M4 18h16M8 4v4M15 10v4M10 16v4",
  settings: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2",
};
export default function NavIcon({ name }: { name: string }) {
  return <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d={P[name] ?? P.overview} /></svg>;
}
