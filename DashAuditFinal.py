#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AuditDash.py — Responsive Security Report Dashboard
---------------------------------------------------
Scans the current folder (optionally recursively) for Markdown (*.md) reports
and builds a single interactive HTML dashboard with filtering, sorting, tabs,
and a responsive layout.

Usage:
  python AuditDash.py
  python AuditDash.py --out audit_dashboard.html --recursive --pattern "*.md"

Optional:
  pip install markdown
"""
from __future__ import annotations

import argparse, json, re
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict

# ------------------------- Markdown renderer -------------------------
def render_markdown(md_text: str) -> str:
    """Convert Markdown to HTML using 'markdown' if available; otherwise escape as <pre>."""
    try:
        import markdown  # type: ignore
        return markdown.markdown(md_text, extensions=["fenced_code", "tables", "toc", "admonition"])
    except Exception:
        safe = (md_text.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))
        return "<pre>" + safe + "</pre>"

# ------------------------- Scoring logic -------------------------
def extract_self_grade_score(md_text: str) -> float:
    m = re.search(r'(?i)\b(self[-\s]?grade|grade)\s*[:\-]\s*([ABCDEF])\b', md_text)
    if not m: return -1.0
    letter = m.group(2).upper()
    mapping = {"A": 95.0, "B": 85.0, "C": 75.0, "D": 60.0, "E": 40.0, "F": 40.0}
    return mapping.get(letter, -1.0)

def count_severities(md_text: str) -> Dict[str, int]:
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for level in list(sev.keys()):
        sev[level] = len(re.findall(rf'(?i)\b{level}\b', md_text))
    return sev

def severity_penalty_score(sev: Dict[str, int]) -> float:
    base = 100.0
    base -= min(sev.get("critical",0) * 25.0, 60.0)
    base -= min(sev.get("high",0) * 15.0, 45.0)
    base -= min(sev.get("medium",0) * 7.0, 35.0)
    base -= min(sev.get("low",0) * 2.0, 10.0)
    return max(1.0, min(100.0, base))

def combine_scores(self_grade: float, sev_score: float) -> float:
    if self_grade < 0: return round(sev_score, 1)
    return round(0.6 * sev_score + 0.4 * self_grade, 1)

# ------------------------- Data model -------------------------
@dataclass
class ReportItem:
    filename: str
    title: str
    html: str
    text: str
    severity: Dict[str, int]
    self_grade_score: float
    severity_score: float
    final_score: float
    mtime: str

# ------------------------- Loader -------------------------
def load_reports(root: Path, recursive: bool = False, pattern: str = "*.md") -> List[ReportItem]:
    files = list(root.rglob(pattern) if recursive else root.glob(pattern))
    out: List[ReportItem] = []
    for p in sorted(files):
        try:
            md = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        html = render_markdown(md)
        sev = count_severities(md)
        ss = severity_penalty_score(sev)
        gs = extract_self_grade_score(md)
        fs = combine_scores(gs, ss)
        m = re.search(r'^\s*#\s+(.+)$', md, re.MULTILINE)
        title = (m.group(1).strip() if m else p.stem)
        mtime = datetime.fromtimestamp(p.stat().st_mtime).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        out.append(ReportItem(
            filename=p.name, title=title, html=html, text=md, severity=sev,
            self_grade_score=gs, severity_score=ss, final_score=fs, mtime=mtime
        ))
    return out

# ------------------------- HTML Template -------------------------
CSS = """
:root{
  --bg:#0b0f14; --panel:#0f1520; --muted:#9bb0c3; --text:#e6edf3; --card:#121a27; --border:#1b2636;
  --accent:#22d3ee; --accent2:#60a5fa; --ok:#22c55e; --warn:#f59e0b; --mid:#f97316; --bad:#ef4444;
  --chip:#0f172a; --chip-border:#1e293b;
}
@media (prefers-color-scheme: light){
  :root{
    --bg:#f7fbff; --panel:#ffffff; --muted:#52667a; --text:#0b0f14; --card:#ffffff; --border:#e6eef6;
    --accent:#0891b2; --accent2:#2563eb; --ok:#16a34a; --warn:#d97706; --mid:#ea580c; --bad:#dc2626;
    --chip:#f8fafc; --chip-border:#e2e8f0;
  }
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family: Inter, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background:var(--bg); color:var(--text)}
.app{display:grid; grid-template-columns: 320px 1fr; min-height:100vh}
.sidebar{background:var(--panel); border-right:1px solid var(--border); padding:16px; position:sticky; top:0; height:100vh; overflow:auto}
.brand{display:flex; gap:10px; align-items:center; margin-bottom:10px}
.logo{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent2))}
.search{display:flex; gap:8px; margin:8px 0 12px}
.search input[type=search]{flex:1; padding:10px 12px; border-radius:10px; border:1px solid var(--border); background:var(--card); color:var(--text)}
.range{display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted); margin-bottom:8px}
.range input{width:100%}
.filters{display:flex; flex-wrap:wrap; gap:8px; margin-bottom:10px}
.chip{background:var(--chip); border:1px solid var(--chip-border); padding:6px 10px; border-radius:999px; font-size:12px; cursor:pointer; user-select:none}
.chip.active{outline:2px solid var(--accent2)}
.sort{margin-bottom:10px}
.list{display:flex; flex-direction:column; gap:6px}
.item{display:flex; justify-content:space-between; align-items:center; padding:10px 12px; border:1px solid var(--border); border-radius:10px; background:var(--card); cursor:pointer}
.item:hover{border-color:var(--accent2)}
.badge{font-weight:800; padding:2px 8px; border-radius:999px; border:1px solid var(--border)}
.content{padding:18px 22px; max-width:1200px; margin:0 auto; width:100%}
.sticky{position:sticky; top:0; background:linear-gradient(var(--bg) 85%, rgba(0,0,0,0)); padding:8px 0 12px; z-index:5}
.topbar{display:flex; align-items:center; justify-content:space-between; gap:12px}
.title{display:flex; gap:10px; align-items:center}
.cards{display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin:12px 0 16px}
.card{background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:14px}
.pill{display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; border:1px solid var(--border); margin-right:8px}
.crit{color:var(--bad)} .high{color:var(--mid)} .med{color:var(--warn)} .low{color:var(--ok)}
.tabs{display:flex; gap:6px; margin:10px 0 12px}
.tab{padding:8px 12px; border-radius:10px; border:1px solid var(--border); background:var(--card); cursor:pointer; font-size:14px}
.tab.active{outline:2px solid var(--accent2)}
.panel{background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:18px}
.md :is(h1,h2){margin-top:20px}
.md h3{margin-top:16px; cursor:pointer}
.md pre{white-space:pre-wrap; word-wrap:break-word; overflow:auto; background:rgba(127,127,127,.08); border:1px solid var(--border); border-radius:10px; padding:10px}
.md code{background:rgba(127,127,127,.12); border:1px solid var(--border); border-radius:6px; padding:2px 5px}
.md table{width:100%; border-collapse:collapse} .md th,.md td{padding:8px; border-bottom:1px solid var(--border)}
.meta{color:var(--muted); font-size:12px}
.hamb{display:none; width:36px; height:36px; border-radius:10px; border:1px solid var(--border); background:var(--card); align-items:center; justify-content:center; cursor:pointer}
@media (max-width: 1000px){
  .app{grid-template-columns: 1fr}
  .sidebar{position:fixed; left:0; top:0; height:100vh; transform:translateX(-100%); transition:transform .25s ease; z-index:20}
  .sidebar.open{transform:translateX(0)}
  .hamb{display:flex; position:fixed; left:12px; top:12px; z-index:25}
  .content{padding-top:60px}
}
"""

HTML_TMPL = """<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>%s</title>
  <style>%s</style>
</head>
<body>
  <div class="app">
    <div id="sidebar" class="sidebar">
      <div class="brand"><div class="logo"></div><h2>Audit Dashboard</h2></div>
      <div class="search">
        <input id="q" type="search" placeholder="Search reports or filenames..."/>
      </div>
      <div class="range">
        <span>Min score</span><input id="minScore" type="range" min="1" max="100" value="1"><span id="minScoreVal">1</span>
      </div>
      <div class="filters">
        <div class="chip" data-sev="critical">Critical</div>
        <div class="chip" data-sev="high">High</div>
        <div class="chip" data-sev="medium">Medium</div>
        <div class="chip" data-sev="low">Low</div>
      </div>
      <div class="sort">
        <select id="sortSel">
          <option value="score">Sort: Score (desc)</option>
          <option value="newest">Sort: Newest</option>
          <option value="name">Sort: Name (A–Z)</option>
        </select>
      </div>
      <div id="list" class="list"></div>
    </div>
    <div class="content">
      <button id="hamb" class="hamb">☰</button>
      <div class="sticky">
        <div class="topbar">
          <div class="title">
            <div class="badge">Security Audit</div>
            <h1 id="title" style="margin:4px 0 0 0">Select a report</h1>
          </div>
          <div id="scoreBadge" class="badge">-</div>
        </div>
        <div class="meta" id="meta"></div>
        <div class="cards">
          <div class="card"><span class="pill crit">Critical</span> <span id="critCount">0</span></div>
          <div class="card"><span class="pill high">High</span> <span id="highCount">0</span></div>
          <div class="card"><span class="pill med">Medium</span> <span id="medCount">0</span></div>
          <div class="card"><span class="pill low">Low</span> <span id="lowCount">0</span></div>
        </div>
        <div class="tabs">
          <div class="tab active" data-tab="summary">Summary</div>
          <div class="tab" data-tab="full">Full Report</div>
        </div>
      </div>
      <div id="panel-summary" class="panel">
        <div class="meta">Use the sidebar filters or search to find the most interesting reports. The summary below will show top headings extracted from the report to help you jump.</div>
        <div id="toc" style="margin-top:12px"></div>
      </div>
      <div id="panel-full" class="panel" style="display:none">
        <div id="md" class="md"><div style="color:var(--muted)">Choose a report from the left to view its contents.</div></div>
      </div>
    </div>
  </div>
<script>
const DATA = %s;
const qs = s => document.querySelector(s);
const qsa = s => Array.from(document.querySelectorAll(s));

function badgeColor(score) {
  const root = getComputedStyle(document.documentElement);
  if (score >= 85) return root.getPropertyValue('--ok').trim();
  if (score >= 70) return root.getPropertyValue('--warn').trim();
  if (score >= 55) return root.getPropertyValue('--mid').trim();
  return root.getPropertyValue('--bad').trim();
}

function renderList() {
  const list = qs("#list");
  const q = qs("#q").value.toLowerCase();
  const minScore = +qs("#minScore").value;
  const chips = qsa(".chip.active").map(x => x.dataset.sev);
  const sortBy = qs("#sortSel").value;

  let arr = DATA.filter(it => (it.title.toLowerCase().includes(q) || it.filename.toLowerCase().includes(q)))
                .filter(it => Math.round(it.final_score) >= minScore);

  if (chips.length) {
    arr = arr.filter(it => chips.some(c => (it.severity[c]||0) > 0));
  }

  if (sortBy === "score") arr.sort((a,b)=>b.final_score - a.final_score);
  if (sortBy === "newest") arr.sort((a,b)=> new Date(b.mtime) - new Date(a.mtime));
  if (sortBy === "name") arr.sort((a,b)=> a.title.localeCompare(b.title));

  list.innerHTML = "";
  arr.forEach((it) => {
    const div = document.createElement("div");
    div.className = "item";
    div.dataset.index = DATA.indexOf(it);
    const left = document.createElement("div");
    left.innerHTML = "<strong>"+it.title+"</strong><div class='meta'>"+it.filename+"</div>";
    const right = document.createElement("div");
    right.className = "badge";
    right.textContent = Math.round(it.final_score);
    const c = badgeColor(it.final_score);
    right.style.borderColor = c; right.style.color = c;
    div.appendChild(left); div.appendChild(right);
    div.onclick = () => select(parseInt(div.dataset.index));
    list.appendChild(div);
  });
}

function buildToc(html) {
  const div = document.createElement("div");
  div.innerHTML = html;
  const headers = div.querySelectorAll("h1,h2,h3");
  const out = [];
  headers.forEach(h => {
    const text = h.textContent;
    const level = parseInt(h.tagName[1]);
    const id = text.toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/(^-|-$)/g,"");
    out.push({id, text, level});
  });
  const toc = qs("#toc");
  toc.innerHTML = out.map(function(o){
    return '<div style="margin-left:' + ((o.level-1)*12) + 'px"><a href="#' + o.id + '">' + o.text + '</a></div>';
  }).join("");
}

function select(idx) {
  const it = DATA[idx];
  qs("#title").textContent = it.title;
  qs("#meta").textContent = it.filename + " • Modified " + it.mtime;
  qs("#critCount").textContent = it.severity.critical || 0;
  qs("#highCount").textContent = it.severity.high || 0;
  qs("#medCount").textContent = it.severity.medium || 0;
  qs("#lowCount").textContent = it.severity.low || 0;
  const sb = qs("#scoreBadge");
  sb.textContent = Math.round(it.final_score);
  const c = badgeColor(it.final_score);
  sb.style.borderColor = c; sb.style.color = c;

  buildToc(it.html);
  qs("#md").innerHTML = it.html;

  // Friendly code blocks
  qsa("#md pre").forEach(p => { p.style.whiteSpace = "pre-wrap"; p.style.wordWrap = "break-word"; p.style.overflow = "auto"; });

  // Collapsible h3 sections
  qsa("#md h3").forEach(h => {
    let open = true;
    h.addEventListener("click", () => {
      open = !open;
      let el = h.nextElementSibling;
      while (el && !/^H[1-3]$/.test(el.tagName)) {
        el.style.display = open ? "" : "none";
        el = el.nextElementSibling;
      }
    });
  });

  // Close sidebar on mobile
  qs("#sidebar").classList.remove("open");
}

function bindUI() {
  qs("#q").addEventListener("input", renderList);
  qs("#minScore").addEventListener("input", (e) => { qs("#minScoreVal").textContent = e.target.value; renderList(); });
  qsa(".chip").forEach(c => c.addEventListener("click", () => { c.classList.toggle("active"); renderList(); }));
  qs("#sortSel").addEventListener("change", renderList);
  qs("#hamb").addEventListener("click", () => qs("#sidebar").classList.toggle("open"));
  // Tabs
  qsa(".tab").forEach(t => t.addEventListener("click", () => {
    qsa(".tab").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    const tab = t.dataset.tab;
    qs("#panel-summary").style.display = (tab === "summary") ? "" : "none";
    qs("#panel-full").style.display = (tab === "full") ? "" : "none";
  }));
}

bindUI();
renderList();
</script>
</body>
</html>
"""

def build_dashboard_html(items: List[ReportItem], title: str = "Security Audit Dashboard") -> str:
    payload = [asdict(i) for i in items]
    data_json = json.dumps(payload).replace("</", "<\\/")  # prevent </script> breakage
    return HTML_TMPL % (title, CSS, data_json)

# ------------------------- CLI -------------------------
def main():
    ap = argparse.ArgumentParser(description="Build an interactive, responsive HTML dashboard from Markdown reports in the current folder.")
    ap.add_argument("--out", type=str, default="audit_dashboard.html", help="Output HTML filename.")
    ap.add_argument("--recursive", action="store_true", help="Scan subfolders recursively.")
    ap.add_argument("--pattern", type=str, default="*.md", help="Glob pattern (default: *.md).")
    args = ap.parse_args()

    items = load_reports(Path("."), recursive=args.recursive, pattern=args.pattern)
    if not items:
        print("No Markdown files found. Put some .md reports in this folder and rerun.")
        return

    html = build_dashboard_html(items, title="Security Audit Dashboard")
    Path(args.out).write_text(html, encoding="utf-8")
    print(f"[+] Wrote {args.out} with {len(items)} report(s).")

if __name__ == "__main__":
    main()
