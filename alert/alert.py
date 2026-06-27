#!/usr/bin/env python3
import json, os, smtplib, sys
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

import requests

BASE_DIR = Path(__file__).parent
SCORES_FILE = BASE_DIR / "last_scores.json"
RESULTS_FILE = Path(os.getenv("RESULTS_FILE", "/opt/domain-monitor/data/results.json"))
DEGRADATION_THRESHOLD = 5
CRITICAL_CHECKS = {"tls_cert", "https", "dnssec"}


def load_env():
    env = {}
    env_path = BASE_DIR.parent / "app" / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    env.update(os.environ)
    return env


def fetch_current_scores():
    if not RESULTS_FILE.exists():
        return {}
    data = json.loads(RESULTS_FILE.read_text())
    scores = {}
    for domain, result in data.get("results", {}).items():
        scores[domain] = {
            "total_score": result.get("total_score"),
            "checks": {k: v.get("status") for k, v in result.get("checks", {}).items()},
        }
    return scores


def load_previous_scores():
    return json.loads(SCORES_FILE.read_text()) if SCORES_FILE.exists() else {}


def detect_degradations(current, previous):
    issues = []
    for domain, cur in current.items():
        prev = previous.get(domain, {})
        domain_issues = []
        cur_score = cur.get("total_score")
        prev_score = prev.get("total_score")
        if cur_score is not None and prev_score is not None:
            drop = prev_score - cur_score
            if drop >= DEGRADATION_THRESHOLD:
                domain_issues.append(f"Score gedaald {drop:.0f}% ({prev_score:.0f}% → {cur_score:.0f}%)")
        for check in CRITICAL_CHECKS:
            if cur.get("checks", {}).get(check) in ("failed", "error"):
                if prev.get("checks", {}).get(check) not in ("failed", "error"):
                    domain_issues.append(f"Kritieke check mislukt: {check}")
        if domain_issues:
            issues.append({"domain": domain, "issues": domain_issues, "score": cur_score})
    return issues


def format_message(degradations):
    lines = [f"Domain Monitor Alert — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
             f"{len(degradations)} domein(en) met verslechtering:\n"]
    for item in degradations:
        lines.append(f"  {item['domain']} (score: {item['score']}%)")
        for issue in item["issues"]:
            lines.append(f"    - {issue}")
    return "\n".join(lines)


def send_email(message, env):
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
    msg["Subject"] = "Domain Monitor: verslechtering gedetecteerd"
    msg["From"] = user
    msg["To"] = to_addr
    with smtplib.SMTP(host, port) as smtp:
        smtp.starttls()
        if user and password:
            smtp.login(user, password)
        smtp.send_message(msg)
    print(f"E-mail verstuurd naar {to_addr}")


def send_telegram(message, env):
    token = env.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = env.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return
    resp = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": message}, timeout=15)
    resp.raise_for_status()
    print(f"Telegram bericht verstuurd naar {chat_id}")


def main():
    env = load_env()
    print(f"Scores laden van {RESULTS_FILE}...")
    current = fetch_current_scores()
    if not current:
        print("Geen scanresultaten gevonden.")
        return
    previous = load_previous_scores()
    degradations = detect_degradations(current, previous)
    if degradations:
        message = format_message(degradations)
        print(message)
        for fn in (send_email, send_telegram):
            try:
                fn(message, env)
            except Exception as exc:
                print(f"Waarschuwing: {exc}", file=sys.stderr)
    else:
        print(f"Alle {len(current)} domeinen OK.")
    SCORES_FILE.write_text(json.dumps(current, indent=2))


if __name__ == "__main__":
    main()
