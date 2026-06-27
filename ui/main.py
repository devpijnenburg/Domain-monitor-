import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

RESULTS_FILE = os.getenv("RESULTS_FILE", "/data/results.json")
DOMAINS_FILE = os.getenv("DOMAINS_FILE", "/data/domains.txt")
TRIGGER_FILE = "/data/scan.trigger"

CHECKS = [
    ("https",    "HTTPS"),
    ("tls_cert", "Cert"),
    ("hsts",     "HSTS"),
    ("ipv6",     "IPv6"),
    ("dnssec",   "DNSSEC"),
    ("spf",      "SPF"),
    ("dmarc",    "DMARC"),
]


def load_domains():
    p = Path(DOMAINS_FILE)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text().splitlines()
            if line.strip() and not line.startswith("#")]


def load_results():
    p = Path(RESULTS_FILE)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    error = None
    domains = []
    scan_date = ""

    try:
        configured = load_domains()
        data = load_results()
        results = data.get("results", {}) if data else {}
        scan_date = data.get("scan_date", "") if data else ""

        seen = set()
        for name in configured:
            seen.add(name)
            result = results.get(name, {})
            score = result.get("total_score")
            checks_raw = result.get("checks", {})
            check_statuses = [
                {"key": k, "label": l,
                 "status": checks_raw.get(k, {}).get("status", "pending"),
                 "detail": checks_raw.get(k, {}).get("detail", "")}
                for k, l in CHECKS
            ]
            domains.append({"name": name, "score": score, "checks": check_statuses})

        for name, result in results.items():
            if name not in seen:
                score = result.get("total_score")
                checks_raw = result.get("checks", {})
                check_statuses = [
                    {"key": k, "label": l,
                     "status": checks_raw.get(k, {}).get("status", "pending"),
                     "detail": checks_raw.get(k, {}).get("detail", "")}
                    for k, l in CHECKS
                ]
                domains.append({"name": name, "score": score, "checks": check_statuses})

        domains.sort(key=lambda d: (d["score"] is None, -(d["score"] or 0)))

        if not configured and not results:
            error = f"Geen domeinen geconfigureerd. Voeg domeinen toe aan {DOMAINS_FILE}."
    except Exception as exc:
        error = f"Fout bij laden: {exc}"

    return templates.TemplateResponse(request, "index.html", context={
        "domains": domains,
        "scan_date": scan_date,
        "error": error,
        "check_labels": [l for _, l in CHECKS],
        "trigger_pending": Path(TRIGGER_FILE).exists(),
    })


@app.post("/scan")
async def trigger_scan():
    try:
        Path(TRIGGER_FILE).touch()
        return JSONResponse({"status": "ok"})
    except Exception as exc:
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=500)
