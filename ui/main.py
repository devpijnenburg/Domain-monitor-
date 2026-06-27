import os
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

API_URL = os.getenv("DASHBOARD_API_URL", "http://web:8000").rstrip("/")
API_TOKEN = os.getenv("DASHBOARD_API_TOKEN", "")

CHECKS = [
    ("https_redirect",            "HTTPS"),
    ("tls_certificate_validity",  "Cert"),
    ("dnssec",                    "DNSSEC"),
    ("hsts",                      "HSTS"),
    ("email_spf",                 "SPF"),
    ("email_dmarc",               "DMARC"),
    ("email_dkim",                "DKIM"),
]


def _headers() -> dict:
    return {"Authorization": f"Token {API_TOKEN}"} if API_TOKEN else {}


async def fetch_domains() -> tuple[list[dict], str, str | None]:
    """Return (domains, scan_date, error)."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{API_URL}/api/v1/report/", headers=_headers())
        resp.raise_for_status()
        reports = resp.json().get("results", [])
        if not reports:
            return [], "", None

        report_id = reports[0]["id"]
        resp = await client.get(
            f"{API_URL}/api/v1/report/{report_id}/", headers=_headers(), timeout=60
        )
        resp.raise_for_status()
        data = resp.json()

    scan_date = data.get("scan_date", "")
    domains = []
    for name, result in data.get("results", {}).items():
        score = result.get("total_score")
        checks_raw = result.get("checks", {})
        check_statuses = []
        for key, label in CHECKS:
            status = (checks_raw.get(key) or {}).get("status", "not_tested")
            check_statuses.append({"label": label, "status": status})

        domains.append({
            "name": name,
            "score": round(score) if score is not None else None,
            "checks": check_statuses,
        })

    domains.sort(key=lambda d: (d["score"] is None, -(d["score"] or 0)))
    return domains, scan_date, None


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    error = None
    domains: list[dict] = []
    scan_date = ""
    host = request.headers.get("host", "").split(":")[0] or "localhost"
    detail_base = f"http://{host}:8000"

    try:
        domains, scan_date, error = await fetch_domains()
    except httpx.HTTPStatusError as exc:
        error = f"API fout {exc.response.status_code}: {exc.response.text[:200]}"
    except Exception as exc:
        error = f"Kan Dashboard API niet bereiken ({API_URL}): {exc}"

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "domains": domains,
            "scan_date": scan_date,
            "error": error,
            "check_labels": [label for _, label in CHECKS],
            "detail_base": detail_base,
        },
    )
