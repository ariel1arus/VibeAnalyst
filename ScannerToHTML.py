#!/usr/bin/env python3
"""
System + Sysmon audit agent with AI analysis (OpenAI or Google Gemini).
Collects system info, recent Sysmon logs, and sends to AI provider for vulnerability analysis.
"""

import os
import sys
import argparse
import json
import datetime as dt
import psutil
from typing import Dict, Any
from pathlib import Path
import re

try:
    from openai import OpenAI
except Exception:
    OpenAI = None  # type: ignore

try:
    import google.generativeai as genai
except Exception:
    genai = None  # type: ignore

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
except Exception:
    evtx = None  # type: ignore

# ---------------------
# Data collection utils
# ---------------------

def collect_system_info() -> Dict[str, Any]:
    info = {
        "cpu_count": psutil.cpu_count(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory": dict(psutil.virtual_memory()._asdict()),
        "swap": dict(psutil.swap_memory()._asdict()),
        "disk_usage": dict(psutil.disk_usage("/")._asdict()),
        "boot_time": dt.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
        "users": [u._asdict() for u in psutil.users()],
    }
    return info

def collect_network_info() -> Dict[str, Any]:
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            conns.append({
                "fd": c.fd, "family": str(c.family), "type": str(c.type),
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                "status": c.status, "pid": c.pid
            })
    except Exception as e:
        conns.append({"error": str(e)})
    return {"connections": conns}

def collect_processes(limit: int = 50) -> Dict[str, Any]:
    procs = []
    for p in psutil.process_iter(attrs=["pid","name","username","cpu_percent","memory_info"]):
        try:
            info = p.info
            info["memory_info"] = dict(info["memory_info"]._asdict())
            procs.append(info)
        except Exception:
            continue
    procs = sorted(procs, key=lambda x: x.get("cpu_percent", 0), reverse=True)
    return {"top_processes": procs[:limit]}

def collect_sysmon_logs(evtx_path: str, hours: int = 24, max_events: int = 200) -> Dict[str, Any]:
    if not evtx:
        return {"error": "python-evtx not installed"}
    if not os.path.exists(evtx_path):
        return {"error": f"Sysmon log not found: {evtx_path}"}
    events = []
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
    try:
        with evtx.Evtx(evtx_path) as log:
            for i, record in enumerate(log.records()):
                try:
                    xml = record.xml()
                    if "<Event" not in xml:
                        continue
                    ts = None
                    if "<TimeCreated SystemTime=" in xml:
                        try:
                            ts = re.search(r'SystemTime="([^"]+)"', xml).group(1)
                            ts = dt.datetime.fromisoformat(ts.replace("Z","+00:00"))
                        except Exception:
                            ts = None
                    if ts and ts < cutoff:
                        continue
                    events.append({"event": xml[:2000]})
                    if len(events) >= max_events:
                        break
                except Exception:
                    continue
    except Exception as e:
        return {"error": str(e)}
    return {"events": events, "count": len(events)}

# ---------------------
# AI prompt + analysis
# ---------------------

def build_prompt(snapshot: Dict[str, Any]) -> str:
    return (
        "You are a cybersecurity professional. Analyze the following live system audit data. "
        "Identify vulnerabilities, suspicious behavior, misconfigurations, and provide CVE references where relevant. "
        "Offer practical mitigations. Grade your findings (A=excellent security posture, F=critical). "
        "Think step by step with analytic reasoning.\n\n"
        f"SNAPSHOT JSON:\n{json.dumps(snapshot, indent=2)}\n"
    )

def send_to_openai_report(snapshot: Dict[str, Any], model: str = "gpt-4.1") -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set in environment.")
    if OpenAI is None:
        raise RuntimeError("openai SDK not installed. Run: pip install openai")
    client = OpenAI(api_key=api_key)
    prompt = build_prompt(snapshot)
    resp = client.responses.create(
        model=model,
        input=prompt,
        temperature=0.2,
        max_output_tokens=2000,
    )
    try:
        return resp.output_text
    except Exception:
        return str(resp)

def send_to_google_report(snapshot: Dict[str, Any], model: str = "gemini-2.0-pro") -> str:
    api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GOOGLEAI_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GOOGLE_API_KEY not set in environment.")
    if genai is None:
        raise RuntimeError("google-generativeai SDK not installed. Run: pip install google-generativeai")
    genai.configure(api_key=api_key)
    prompt = build_prompt(snapshot)
    model_obj = genai.GenerativeModel(model)
    resp = model_obj.generate_content(prompt, safety_settings=None, generation_config={
        "temperature": 0.2,
        "max_output_tokens": 3000,
    })
    if hasattr(resp, "text") and resp.text:
        return resp.text
    return "No text output parsed from Google response."

def send_to_ai_report(snapshot: Dict[str, Any], provider: str = "openai", model: str = "") -> str:
    provider = (provider or "openai").lower()
    if provider == "google":
        use_model = model or "gemini-2.0-pro"
        return send_to_google_report(snapshot, model=use_model)
    else:
        use_model = model or "gpt-4.1"
        return send_to_openai_report(snapshot, model=use_model)

# ---------------------
# Main CLI
# ---------------------


# ---------------------
# Markdown → HTML renderer + score
# ---------------------

def _extract_self_grade(md_text: str) -> float:
    """
    Parse self-grade (A–F) and convert to score (A=95, B=85, C=75, D=60, F/E=40).
    Returns -1.0 if not found.
    """
    # Look for lines like: "Grade: A" or "Self-Grade: A–"
    m = re.search(r'(?i)grade\s*[:\-]\s*([ABCDEF])', md_text)
    if not m:
        return -1.0
    letter = m.group(1).upper()
    mapping = {"A": 95.0, "B": 85.0, "C": 75.0, "D": 60.0, "E": 40.0, "F": 40.0}
    return mapping.get(letter, -1.0)

def _count_severities(md_text: str) -> dict:
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    # Count headings or labels like "Risk: High" or "[High]"
    for level in sev.keys():
        sev[level] = len(re.findall(rf'(?i)\b{level}\b', md_text))
    return sev

def _severity_penalty_score(sev: dict) -> float:
    """
    Start from 100, subtract weighted penalties (capped) and clamp to [1, 100].
    """
    base = 100.0
    # Weights per finding; caps keep things sane if the report is large
    base -= min(sev.get("critical",0) * 25.0, 60.0)
    base -= min(sev.get("high",0) * 15.0, 45.0)
    base -= min(sev.get("medium",0) * 7.0, 35.0)
    base -= min(sev.get("low",0) * 2.0, 10.0)
    return max(1.0, min(100.0, base))

def _combine_scores(self_grade: float, sev_score: float) -> float:
    """
    If self-grade present, average it with severity score (weighted 40% grade, 60% severity).
    Otherwise return severity score.
    """
    if self_grade < 0:
        return float(sev_score)
    return round(0.6 * sev_score + 0.4 * self_grade, 1)

def compute_security_score(md_text: str) -> dict:
    sev = _count_severities(md_text)
    sev_score = _severity_penalty_score(sev)
    letter_score = _extract_self_grade(md_text)
    final = _combine_scores(letter_score, sev_score)
    return {"final_score": final, "severity_counts": sev, "self_grade_score": letter_score, "severity_score": sev_score}

def render_markdown_to_html(md_text: str, title: str = "Security Audit Report") -> str:
    try:
        import markdown  # pip install markdown
    except Exception:
        # Minimal fallback if markdown lib not present
        safe = (md_text
                .replace("&","&amp;")
                .replace("<","&lt;")
                .replace(">","&gt;"))
        return f"<html><head><meta charset='utf-8'><title>{title}</title></head><body><pre>{safe}</pre></body></html>"

    score_obj = compute_security_score(md_text)
    score = score_obj["final_score"]

    # Basic styling
    css = """
    body { font-family: Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 24px; color: #111; }
    .hero { display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .badge { font-size: 42px; font-weight: 800; padding: 12px 20px; border-radius: 16px; background:#111; color:#fff; }
    .meta { color:#555; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin: 16px 0; }
    .card { border:1px solid #e6e6e6; border-radius: 12px; padding: 16px; background:#fff; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { text-align:left; padding: 8px; border-bottom: 1px solid #eee; }
    .crit { color: #b00020; font-weight: 700; }
    .high { color: #d35400; font-weight: 700; }
    .med { color: #c3a000; font-weight: 700; }
    .low { color: #2c7a7b; font-weight: 700; }
    .content { margin-top: 24px; }
    code, pre { background: #f7f7f9; border-radius: 6px; }
    """
    try:
        from datetime import datetime, timezone
        nowstr = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        nowstr = ""

    # Markdown conversion
    html_body = markdown.markdown(md_text, extensions=["fenced_code", "tables", "toc", "admonition"])

    sev = score_obj["severity_counts"]
    badge_color = "#067d68" if score >= 85 else "#c3a000" if score >= 70 else "#d35400" if score >= 55 else "#b00020"

    # Header + metrics
    head = f"""
    <div class="hero">
      <div>
        <h1>{title}</h1>
        <div class="meta">Generated: {nowstr}</div>
      </div>
      <div class="badge" style="background:{badge_color}">{int(round(score))}/100</div>
    </div>

    <div class="grid">
      <div class="card">
        <div><span class="crit">Critical</span>: {sev.get('critical',0)}</div>
        <div><span class="high">High</span>: {sev.get('high',0)}</div>
        <div><span class="med">Medium</span>: {sev.get('medium',0)}</div>
        <div><span class="low">Low</span>: {sev.get('low',0)}</div>
      </div>
      <div class="card">
        <div><strong>Severity-based score</strong>: {int(round(score_obj['severity_score']))}</div>
        <div><strong>Self-grade score</strong>: {('N/A' if score_obj['self_grade_score']<0 else int(round(score_obj['self_grade_score'])) )}</div>
        <div><strong>Final score</strong>: {int(round(score))}</div>
      </div>
    </div>
    """

    return f"<html><head><meta charset='utf-8'><title>{title}</title><style>{css}</style></head><body>{head}<div class='content'>{html_body}</div></body></html>"

def write_html_from_md(md_path: str, html_out: str, title: str = None) -> str:
    p = Path(md_path)
    md = p.read_text(encoding="utf-8", errors="ignore")
    html = render_markdown_to_html(md, title or p.stem)
    Path(html_out).write_text(html, encoding="utf-8")
    return html_out
def main():
    parser = argparse.ArgumentParser(description="Collect system+Sysmon data and obtain AI security analysis.")
    parser.add_argument("--from-md", type=str, default="", help="Convert an existing Markdown report to HTML and exit.")
    parser.add_argument("--html-out", type=str, default="", help="Write HTML to this path (optional).")
    parser.add_argument("--hours", type=int, default=24, help="How many hours back to collect Sysmon logs.")
    parser.add_argument("--max-sysmon", type=int, default=300, help="Max Sysmon events to parse.")
    parser.add_argument("--sysmon-path", type=str, default=r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx", help="Path to Sysmon EVTX file.")
    parser.add_argument("--provider", type=str, default="openai", choices=["openai","google"], help="Which AI provider to use.")
    parser.add_argument("--model", type=str, default="", help="Model name (defaults: openai=gpt-4.1, google=gemini-2.0-pro).")
    args = parser.parse_args()

    if args.from_md:
        out_html = args.html_out or (Path(args.from_md).with_suffix(".html").name)
        write_html_from_md(args.from_md, out_html)
        print(f"[+] Wrote HTML: {out_html}")
        return

    snapshot = {
        "system": collect_system_info(),
        "network": collect_network_info(),
        "processes": collect_processes(),
        "sysmon": collect_sysmon_logs(args.sysmon_path, hours=args.hours, max_events=args.max_sysmon),
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }

    try:
        report_md = send_to_ai_report(snapshot, provider=args.provider, model=args.model)
    except Exception as e:
        report_md = f"# AI Analysis Error\n\n{e}\n"

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"security_audit_{os.environ.get('USERNAME','user')}_{ts}"
    md_path = Path(f"{base}.md")
    json_path = Path(f"{base}_snapshot.json")

    md_path.write_text(report_md, encoding="utf-8")
    json_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

    print(f"[+] Wrote report: {md_path}")
    print(f"[+] Wrote snapshot: {json_path}")
    if args.html_out:
        out_html = args.html_out
    else:
        out_html = md_path.with_suffix(".html")
    try:
        write_html_from_md(str(md_path), str(out_html))
        print(f"[+] Wrote HTML: {out_html}")
    except Exception as e:
        print(f"[!] HTML render failed: {e}")

if __name__ == "__main__":
    main()
