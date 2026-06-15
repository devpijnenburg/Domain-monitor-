#!/usr/bin/env python3
"""
Polls the internet.nl Dashboard API for the latest scan results,
compares them to the previous baseline, and sends alerts via SMTP
and/or Telegram when a domain's score degrades.
"""

import json
import os
import smtplib
import sys
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

import requests

BASE_DIR = Path(__file__).parent
SCORES_FILE = BASE_DIR / "last_scores.json"
DEGRADATION_THRESHOLD = 5  # alert when score drops >= 5 percentage points

CRITICAL_CHECKS = {
    "dnssec",
    "tls_certificate_validity",
    "https_redirect",
}


def load_env() -> dict:
    env_path = BASE_DIR.parent / "app" / ".env"
    env = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                env[key.strip()] = val.strip()
    env.update(os.environ)
    return env


def fetch_latest_scores(api_url: str, api_token: str) -> dict[str, dict]:
    headers = {"Authorization": f"Token {api_token}"} if api_token else {}
    resp = requests.get(f"{api_url}/api/v1/report/", headers=headers, timeout=30)
    resp.raise_for_status()
    reports = resp.json().get("results", [])
    if not reports:
        return {}

    latest = reports[0]
    report_id = latest["id"]

    resp = requests.get(f"{api_url}/api/v1/report/{report_id}/", headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    scores = {}
    for domain, result in data.get("results", {}).items():
        scores[domain] = {
            "total_score": result.get("total_score"),
            "checks": {
                k: v.get("status")
                for k, v in result.get("checks", {}).items()
            },
            "scan_date": data.get("scan_date", ""),
        }
    return scores


def load_previous_scores() -> dict:
    if SCORES_FILE.exists():
        return json.loads(SCORES_FILE.read_text())
    return {}


def save_scores(scores: dict) -> None:
    SCORES_FILE.write_text(json.dumps(scores, indent=2))


def detect_degradations(current: dict, previous: dict) -> list[dict]:
    issues = []
    for domain, cur in current.items():
        prev = previous.get(domain)
        domain_issues = []

        if prev is not None:
            cur_score = cur.get("total_score")
            prev_score = prev.get("total_score")
            if cur_score is not None and prev_score is not None:
                drop = prev_score - cur_score
                if drop >= DEGRADATION_THRESHOLD:
                    domain_issues.append(
                        f"Total score dropped {drop:.1f}% ({prev_score:.1f}% → {cur_score:.1f}%)"
                    )

        for check in CRITICAL_CHECKS:
            status = cur.get("checks", {}).get(check)
            prev_status = (prev or {}).get("checks", {}).get(check)
            if status in ("failed", "error") and prev_status not in ("failed", "error"):
                domain_issues.append(f"Critical check FAILED: {check} (was: {prev_status})")

        if domain_issues:
            issues.append({"domain": domain, "issues": domain_issues, "score": cur.get("total_score")})

    return issues


def format_message(degradations: list[dict]) -> str:
    lines = [f"Domain Monitor Alert — {datetime.now().strftime('%Y-%m-%d %H:%M')}"]
    lines.append(f"{len(degradations)} domain(s) with degraded scores:\n")
    for item in degradations:
        lines.append(f"  {item['domain']} (score: {item['score']}%)")
        for issue in item["issues"]:
            lines.append(f"    - {issue}")
    return "\n".join(lines)


def send_email(message: str, env: dict) -> None:
    host = env.get("SMTP_HOST", "")
    if not host:
        return
    port = int(env.get("SMTP_PORT", 587))
    user = env.get("SMTP_USER", "")
    password = env.get("SMTP_PASSWORD", "")
    to_addr = env.get("ALERT_EMAIL_TO", "")
    if not to_addr:
        return

    msg = MIMEText(message)
    msg["Subject"] = "Domain Monitor: Score degradation detected"
    msg["From"] = user
    msg["To"] = to_addr

    with smtplib.SMTP(host, port) as smtp:
        smtp.starttls()
        if user and password:
            smtp.login(user, password)
        smtp.send_message(msg)
    print(f"Email alert sent to {to_addr}")


def send_telegram(message: str, env: dict) -> None:
    token = env.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = env.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    resp = requests.post(url, json={"chat_id": chat_id, "text": message}, timeout=15)
    resp.raise_for_status()
    print(f"Telegram alert sent to chat {chat_id}")


def main() -> None:
    env = load_env()
    api_url = env.get("DASHBOARD_API_URL", "http://localhost:8000").rstrip("/")
    api_token = env.get("DASHBOARD_API_TOKEN", "")

    print(f"Fetching latest scores from {api_url}...")
    try:
        current = fetch_latest_scores(api_url, api_token)
    except Exception as exc:
        print(f"ERROR fetching scores: {exc}", file=sys.stderr)
        sys.exit(1)

    if not current:
        print("No scan results found — skipping alert check.")
        return

    previous = load_previous_scores()
    degradations = detect_degradations(current, previous)

    if degradations:
        message = format_message(degradations)
        print(message)
        try:
            send_email(message, env)
        except Exception as exc:
            print(f"Email error: {exc}", file=sys.stderr)
        try:
            send_telegram(message, env)
        except Exception as exc:
            print(f"Telegram error: {exc}", file=sys.stderr)
    else:
        print(f"All {len(current)} domains OK — no degradation detected.")

    save_scores(current)


if __name__ == "__main__":
    main()
