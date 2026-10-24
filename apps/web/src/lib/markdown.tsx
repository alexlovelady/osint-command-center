// Small, safe Markdown renderer for assistant replies: builds React elements (no innerHTML). Supports paragraphs, lists, bold, italics, code, quotes and
// [c1]/[d1] citation markers. Links are not rendered as links, so model output cannot create a clickable address.
import type { ReactNode } from "react";

const INLINE = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*\n]+\*|\[[cd]\d{1,3}\])/g;

function inline(text: string, key: string, cite?: (ref: string) => void): ReactNode[] {
  return text.split(INLINE).filter((s) => s !== "").map((part, i) => {
    const k = `${key}-${i}`;
    if (part.startsWith("**") && part.endsWith("**") && part.length > 4) return <strong key={k}>{part.slice(2, -2)}</strong>;
    if (part.startsWith("`") && part.endsWith("`") && part.length > 2) return <code key={k}>{part.slice(1, -1)}</code>;
    if (part.startsWith("*") && part.endsWith("*") && part.length > 2) return <em key={k}>{part.slice(1, -1)}</em>;
    const m = /^\[([cd]\d{1,3})\]$/.exec(part);
    if (m) return <button key={k} type="button" className="cite" onClick={() => cite?.(m[1])} aria-label={`Source ${m[1]}`}>{m[1]}</button>;
    return part;
  });
}

export function Markdown({ text, onCite }: { text: string; onCite?: (ref: string) => void }) {
  const out: ReactNode[] = [];
  const lines = text.split("\n");
  let i = 0;
  let n = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    if (/^\s*[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*[-*]\s+/, "")); i++; }
      out.push(<ul key={n++}>{items.map((t, j) => <li key={j}>{inline(t, `u${n}-${j}`, onCite)}</li>)}</ul>);
    } else if (/^\s*\d+[.)]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*\d+[.)]\s+/, "")); i++; }
      out.push(<ol key={n++}>{items.map((t, j) => <li key={j}>{inline(t, `o${n}-${j}`, onCite)}</li>)}</ol>);
    } else if (line.startsWith(">")) {
      const q: string[] = [];
      while (i < lines.length && lines[i].startsWith(">")) { q.push(lines[i].replace(/^>\s?/, "")); i++; }
      out.push(<blockquote key={n++}>{inline(q.join(" "), `q${n}`, onCite)}</blockquote>);
    } else {
      const p: string[] = [];
      while (i < lines.length && lines[i].trim() && !/^\s*([-*]|\d+[.)])\s+/.test(lines[i]) && !lines[i].startsWith(">")) { p.push(lines[i]); i++; }
      out.push(<p key={n++}>{inline(p.join(" "), `p${n}`, onCite)}</p>);
    }
  }
  return <div className="md">{out}</div>;
}
