import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

RESULTS_FILE = os.getenv("RESULTS_FILE", "/data/results.json")

CHECKS = [
    ("https",    "HTTPS"),
    ("tls_cert", "Cert"),
    ("hsts",     "HSTS"),
    ("ipv6",     "IPv6"),
    ("dnssec",   "DNSSEC"),
    ("spf",      "SPF"),
    ("dmarc",    "DMARC"),
]


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
        data = load_results()
        if data is None:
            error = f"Nog geen scanresultaten. Wacht tot de monitor-service klaar is, of controleer {RESULTS_FILE}."
        else:
            scan_date = data.get("scan_date", "")
            for name, result in data.get("results", {}).items():
                score = result.get("total_score")
                checks_raw = result.get("checks", {})
                check_statuses = [
                    {"key": k, "label": l, "status": checks_raw.get(k, {}).get("status", "not_tested"),
                     "detail": checks_raw.get(k, {}).get("detail", "")}
                    for k, l in CHECKS
                ]
                domains.append({"name": name, "score": score, "checks": check_statuses})
            domains.sort(key=lambda d: (d["score"] is None, -(d["score"] or 0)))
    except Exception as exc:
        error = f"Fout bij laden resultaten: {exc}"

    return templates.TemplateResponse("index.html", {
        "request": request,
        "domains": domains,
        "scan_date": scan_date,
        "error": error,
        "check_labels": [l for _, l in CHECKS],
    })
