# Theme system: preset `ops-hybrid` (alias `blacksite-ghost`)

A hybrid of **Blacksite Redline** (amber primary, red for urgency, serious command-centre tone) and **Ghost Grid** (teal for signal, telemetry, maps and
graphs, a faint grid texture). Dark is the default; a light scheme follows the OS setting. All colour lives in `apps/web/src/theme.css`.

## Semantic tokens (`--c-*`)

| Group | Tokens |
|---|---|
| Surfaces | `--c-bg`, `--c-panel`, `--c-elevated`, `--c-sunken`, `--c-border`, `--c-border-strong` |
| Text | `--c-text`, `--c-text-2`, `--c-text-inverse` |
| Accent (amber, operational) | `--c-accent` (fills), `--c-accent-strong` (hover), `--c-accent-text` (text on panels), `--c-accent-wash` |
| Technical (teal, signal/grid) | `--c-tech`, `--c-tech-text`, `--c-tech-wash` |
| Status | `--c-ok/-text`, `--c-warn/-text`, `--c-danger/-text/-wash` |
| Interaction | `--c-nav-active-bg`, `--c-nav-active-bar`, `--c-hover`, `--c-focus`, `--c-scrim` |
| Charts / graph / map | `--chart-1..5` (amber, teal, red, grey, green), `--chart-edge`, `--chart-label`, `--map-tile-filter`, `--c-grid` |
| Type | `--font` (system UI stack), `--font-mono` |

The old names (`--bg`, `--panel`, `--accent`, `--warn`, `--bad`, `--ok`, `--muted`, `--line`) remain as aliases of these tokens so nothing else needed rewriting.
Fills may be darker than the matching `*-text` token: text tokens are the ones tested for contrast (axe, light and dark, every page and case tab).

## Components

* Panels are squared, bordered modules with a top amber (or teal) rule on stat cards; `.card.tone-alert` (Redline: red edge and wash) and `.card.tone-tech` (Ghost Grid: teal edge and wash) give alert and signal modules their own flavour.
* Sidebar: icon + label, active item amber with a bar. Badges are small uppercase status tags (green/amber/red).
* Copilot: console look: teal model strip with a status dot, amber user bubbles, teal-edged assistant bubbles, mono source chips.
* Graph (Cytoscape) and map (Leaflet) read the chart tokens at runtime through `lib/theme.ts` (`chart()`), so they follow the scheme; map tiles are darkened with `--map-tile-filter`.

To make another preset, override the `--c-*` and `--chart-*` tokens under a new selector; no component code needs to change.
