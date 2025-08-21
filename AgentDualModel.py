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

def main():
    parser = argparse.ArgumentParser(description="Collect system+Sysmon data and obtain AI security analysis.")
    parser.add_argument("--hours", type=int, default=24, help="How many hours back to collect Sysmon logs.")
    parser.add_argument("--max-sysmon", type=int, default=300, help="Max Sysmon events to parse.")
    parser.add_argument("--sysmon-path", type=str, default=r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx", help="Path to Sysmon EVTX file.")
    parser.add_argument("--provider", type=str, default="openai", choices=["openai","google"], help="Which AI provider to use.")
    parser.add_argument("--model", type=str, default="", help="Model name (defaults: openai=gpt-4.1, google=gemini-2.0-pro).")
    args = parser.parse_args()

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

if __name__ == "__main__":
    main()
