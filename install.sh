#!/usr/bin/env bash
# Domain Monitor — one-liner installer
# bash -c "$(curl -fsSL https://raw.githubusercontent.com/devpijnenburg/Domain-monitor-/main/install.sh)"
set -euo pipefail

INSTALL_DIR="/opt/domain-monitor"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && die "Voer dit script uit als root."

# ════════════════════════════════════════════════════════════════════════════
# Bestanden: alle app-inhoud als heredoc naar een staging map schrijven
# ════════════════════════════════════════════════════════════════════════════

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT
mkdir -p "$STAGING/app" "$STAGING/alert" "$STAGING/config" "$STAGING/ui/templates"

# ── docker-compose.yml ──────────────────────────────────────────────────────
cat > "$STAGING/app/docker-compose.yml" <<'COMPOSE'
services:
  db:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: dashboard
      POSTGRES_USER: dashboard
      POSTGRES_PASSWORD: ${DB_PASSWORD:-changeme}
    volumes:
      - db_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U dashboard"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  web:
    image: ghcr.io/internetstandards/dashboard:latest
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    ports:
      - "8000:8000"
    environment:
      SECRET_KEY: ${SECRET_KEY:-changeme}
      DB_HOST: db
      DB_NAME: dashboard
      DB_USER: dashboard
      DB_PASSWORD: ${DB_PASSWORD:-changeme}
      REDIS_URL: redis://redis:6379/0
      ALLOWED_HOSTS: "*"
      DJANGO_SETTINGS_MODULE: dashboard.settings.docker
    volumes:
      - app_data:/app/data
    command: gunicorn dashboard.wsgi:application --bind 0.0.0.0:8000 --workers 2

  worker:
    image: ghcr.io/internetstandards/dashboard:latest
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      SECRET_KEY: ${SECRET_KEY:-changeme}
      DB_HOST: db
      DB_NAME: dashboard
      DB_USER: dashboard
      DB_PASSWORD: ${DB_PASSWORD:-changeme}
      REDIS_URL: redis://redis:6379/0
      DJANGO_SETTINGS_MODULE: dashboard.settings.docker
    volumes:
      - app_data:/app/data
    command: celery -A dashboard worker --loglevel=info --concurrency=2

  scheduler:
    image: ghcr.io/internetstandards/dashboard:latest
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      SECRET_KEY: ${SECRET_KEY:-changeme}
      DB_HOST: db
      DB_NAME: dashboard
      DB_USER: dashboard
      DB_PASSWORD: ${DB_PASSWORD:-changeme}
      REDIS_URL: redis://redis:6379/0
      DJANGO_SETTINGS_MODULE: dashboard.settings.docker
    volumes:
      - app_data:/app/data
    command: celery -A dashboard beat --loglevel=info --scheduler django_celery_beat.schedulers:DatabaseScheduler

  ui:
    image: python:3.12-slim
    restart: unless-stopped
    working_dir: /app
    volumes:
      - ../ui:/app
    ports:
      - "3000:3000"
    environment:
      DASHBOARD_API_URL: http://web:8000
      DASHBOARD_API_TOKEN: ${DASHBOARD_API_TOKEN:-}
    depends_on:
      web:
        condition: service_started
    command: >
      sh -c "pip install -q -r requirements.txt &&
             uvicorn main:app --host 0.0.0.0 --port 3000"

volumes:
  db_data:
  redis_data:
  app_data:
COMPOSE

# ── alert/alert.py ──────────────────────────────────────────────────────────
cat > "$STAGING/alert/alert.py" <<'PYEOF'
#!/usr/bin/env python3
import json, os, smtplib, sys
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

import requests

BASE_DIR = Path(__file__).parent
SCORES_FILE = BASE_DIR / "last_scores.json"
DEGRADATION_THRESHOLD = 5
CRITICAL_CHECKS = {"dnssec", "tls_certificate_validity", "https_redirect"}

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

def fetch_latest_scores(api_url, api_token):
    headers = {"Authorization": f"Token {api_token}"} if api_token else {}
    resp = requests.get(f"{api_url}/api/v1/report/", headers=headers, timeout=30)
    resp.raise_for_status()
    reports = resp.json().get("results", [])
    if not reports:
        return {}
    report_id = reports[0]["id"]
    resp = requests.get(f"{api_url}/api/v1/report/{report_id}/", headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
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
                domain_issues.append(f"Score gedaald {drop:.1f}% ({prev_score:.1f}% → {cur_score:.1f}%)")
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
    api_url = env.get("DASHBOARD_API_URL", "http://localhost:8000").rstrip("/")
    api_token = env.get("DASHBOARD_API_TOKEN", "")
    print(f"Scores ophalen van {api_url}...")
    try:
        current = fetch_latest_scores(api_url, api_token)
    except Exception as exc:
        print(f"FOUT: {exc}", file=sys.stderr)
        sys.exit(1)
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
        print(f"Alle {len(current)} domeinen OK — geen verslechtering.")
    SCORES_FILE.write_text(json.dumps(current, indent=2))

if __name__ == "__main__":
    main()
PYEOF

cat > "$STAGING/alert/cron.sh" <<'CRONEOF'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec python3 alert.py
CRONEOF
chmod +x "$STAGING/alert/cron.sh"

cat > "$STAGING/alert/requirements.txt" <<'REQEOF'
requests>=2.31.0
python-telegram-bot>=20.0
REQEOF

# ── ui/main.py ──────────────────────────────────────────────────────────────
cat > "$STAGING/ui/requirements.txt" <<'UIREQEOF'
fastapi>=0.111.0
uvicorn[standard]>=0.29.0
jinja2>=3.1.4
httpx>=0.27.0
UIREQEOF

cat > "$STAGING/ui/main.py" <<'UIMAINEOF'
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
    ("https_redirect",           "HTTPS"),
    ("tls_certificate_validity", "Cert"),
    ("dnssec",                   "DNSSEC"),
    ("hsts",                     "HSTS"),
    ("email_spf",                "SPF"),
    ("email_dmarc",              "DMARC"),
    ("email_dkim",               "DKIM"),
]

def _headers():
    return {"Authorization": f"Token {API_TOKEN}"} if API_TOKEN else {}

async def fetch_domains():
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{API_URL}/api/v1/report/", headers=_headers())
        resp.raise_for_status()
        reports = resp.json().get("results", [])
        if not reports:
            return [], "", None
        report_id = reports[0]["id"]
        resp = await client.get(f"{API_URL}/api/v1/report/{report_id}/", headers=_headers(), timeout=60)
        resp.raise_for_status()
        data = resp.json()
    scan_date = data.get("scan_date", "")
    domains = []
    for name, result in data.get("results", {}).items():
        score = result.get("total_score")
        checks_raw = result.get("checks", {})
        check_statuses = [{"label": l, "status": (checks_raw.get(k) or {}).get("status", "not_tested")} for k, l in CHECKS]
        domains.append({"name": name, "score": round(score) if score is not None else None, "checks": check_statuses})
    domains.sort(key=lambda d: (d["score"] is None, -(d["score"] or 0)))
    return domains, scan_date, None

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    error = None
    domains, scan_date = [], ""
    host = request.headers.get("host", "").split(":")[0] or "localhost"
    detail_base = f"http://{host}:8000"
    try:
        domains, scan_date, error = await fetch_domains()
    except httpx.HTTPStatusError as exc:
        error = f"API fout {exc.response.status_code}: {exc.response.text[:200]}"
    except Exception as exc:
        error = f"Kan Dashboard API niet bereiken ({API_URL}): {exc}"
    return templates.TemplateResponse("index.html", {
        "request": request, "domains": domains, "scan_date": scan_date,
        "error": error, "check_labels": [l for _, l in CHECKS], "detail_base": detail_base,
    })
UIMAINEOF

cat > "$STAGING/ui/templates/index.html" <<'UIHTMLEOF'
<!DOCTYPE html>
<html lang="nl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="60">
  <title>Domain Monitor</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; padding: 2rem 1rem; }
    header { max-width: 1100px; margin: 0 auto 2rem; display: flex; align-items: baseline; gap: 1.5rem; flex-wrap: wrap; }
    h1 { font-size: 1.6rem; font-weight: 700; color: #f1f5f9; }
    .meta { font-size: 0.8rem; color: #64748b; }
    .refresh-note { margin-left: auto; font-size: 0.75rem; color: #475569; }
    .error { max-width: 1100px; margin: 0 auto 1.5rem; background: #450a0a; border: 1px solid #b91c1c; border-radius: 8px; padding: 1rem 1.25rem; color: #fca5a5; font-size: 0.9rem; }
    .card { max-width: 1100px; margin: 0 auto; background: #1e293b; border-radius: 12px; overflow: hidden; border: 1px solid #334155; }
    table { width: 100%; border-collapse: collapse; }
    thead tr { background: #0f172a; border-bottom: 1px solid #334155; }
    th { padding: 0.75rem 1rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; text-align: left; }
    th.center, td.center { text-align: center; }
    tbody tr { border-bottom: 1px solid #1e293b; transition: background 0.15s; }
    tbody tr:last-child { border-bottom: none; }
    tbody tr:hover { background: #263348; }
    td { padding: 0.85rem 1rem; font-size: 0.9rem; vertical-align: middle; }
    .domain-name { font-weight: 600; color: #f1f5f9; font-size: 0.95rem; }
    .score { display: inline-flex; align-items: center; justify-content: center; width: 3rem; height: 1.75rem; border-radius: 6px; font-size: 0.8rem; font-weight: 700; }
    .score-green { background: #14532d; color: #4ade80; }
    .score-yellow { background: #713f12; color: #fbbf24; }
    .score-red { background: #450a0a; color: #f87171; }
    .score-none { background: #1e293b; color: #475569; }
    .check { display: inline-flex; align-items: center; justify-content: center; width: 1.6rem; height: 1.6rem; border-radius: 50%; font-size: 0.75rem; font-weight: 700; }
    .check-passed { background: #14532d; color: #4ade80; }
    .check-failed { background: #450a0a; color: #f87171; }
    .check-warning { background: #713f12; color: #fbbf24; }
    .check-other { background: #1e293b; color: #475569; }
    .btn-detail { display: inline-block; padding: 0.35rem 0.7rem; background: #1e40af; color: #bfdbfe; border-radius: 6px; text-decoration: none; font-size: 0.75rem; font-weight: 600; transition: background 0.15s; }
    .btn-detail:hover { background: #2563eb; color: #fff; }
    .empty { text-align: center; padding: 3rem; color: #475569; }
    @media (max-width: 700px) { .hide-mobile { display: none; } }
  </style>
</head>
<body>
<header>
  <h1>Domain Monitor</h1>
  {% if scan_date %}<span class="meta">Laatste scan: {{ scan_date[:16] | replace("T", " ") }}</span>{% endif %}
  <span class="refresh-note">Vernieuwt elke 60s</span>
</header>
{% if error %}
<div class="error"><strong>Fout:</strong> {{ error }}<br><small>Zorg dat de internet.nl Dashboard service actief is op poort 8000.</small></div>
{% endif %}
<div class="card">
  {% if domains %}
  <table>
    <thead><tr>
      <th>Domein</th><th class="center">Score</th>
      {% for label in check_labels %}<th class="center hide-mobile">{{ label }}</th>{% endfor %}
      <th class="center">Details</th>
    </tr></thead>
    <tbody>
      {% for d in domains %}
      <tr>
        <td class="domain-name">{{ d.name }}</td>
        <td class="center">
          {% if d.score is not none %}
            {% if d.score >= 80 %}<span class="score score-green">{{ d.score }}%</span>
            {% elif d.score >= 60 %}<span class="score score-yellow">{{ d.score }}%</span>
            {% else %}<span class="score score-red">{{ d.score }}%</span>{% endif %}
          {% else %}<span class="score score-none">–</span>{% endif %}
        </td>
        {% for check in d.checks %}
        <td class="center hide-mobile">
          {% if check.status == "passed" %}<span class="check check-passed" title="{{ check.label }}: OK">✓</span>
          {% elif check.status == "failed" %}<span class="check check-failed" title="{{ check.label }}: Mislukt">✗</span>
          {% elif check.status == "warning" %}<span class="check check-warning" title="{{ check.label }}: Waarschuwing">!</span>
          {% else %}<span class="check check-other" title="{{ check.label }}: Niet getest">–</span>{% endif %}
        </td>
        {% endfor %}
        <td class="center"><a class="btn-detail" href="{{ detail_base }}" target="_blank">→</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% elif not error %}
  <div class="empty">Nog geen scanresultaten.<br><small>Voeg domeinen toe en start een scan via de <a href="{{ detail_base }}" style="color:#60a5fa">internet.nl Dashboard</a>.</small></div>
  {% endif %}
</div>
</body>
</html>
UIHTMLEOF

cat > "$STAGING/config/domains.txt" <<'DOMEOF'
# Voeg hier je domeinen toe, één per regel
# example.com
DOMEOF

# ════════════════════════════════════════════════════════════════════════════
# Interactieve configuratie
# ════════════════════════════════════════════════════════════════════════════

echo ""
if command -v pct &>/dev/null; then
    echo "Proxmox VE gedetecteerd — de applicatie wordt in een LXC container geïnstalleerd."
    echo ""
    read -rp  "LXC VMID [200]: "                VMID;       [[ -z "$VMID" ]]       && VMID=200
    read -rp  "LXC naam [domain-monitor]: "     LXC_NAME;   [[ -z "$LXC_NAME" ]]   && LXC_NAME="domain-monitor"
    read -rp  "Netwerk bridge [vmbr0]: "        BRIDGE;     [[ -z "$BRIDGE" ]]     && BRIDGE="vmbr0"
    read -rp  "Geheugen MB [2048]: "            LXC_MEM;    [[ -z "$LXC_MEM" ]]    && LXC_MEM=2048
    read -rp  "Opslag pool [local-lvm]: "       STORAGE;    [[ -z "$STORAGE" ]]    && STORAGE="local-lvm"
    PROXMOX_MODE=1
else
    PROXMOX_MODE=0
fi

echo ""
log "Configuratie invullen..."
echo ""

read -rp "Database wachtwoord (Enter = willekeurig): " DB_PASS
[[ -z "$DB_PASS" ]] && DB_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
SECRET_KEY=$(tr -dc 'A-Za-z0-9!@#%^&*' </dev/urandom | head -c 60)

echo ""
echo "─── SMTP e-mail alerts (leeg = uitgeschakeld) ───────────────────"
read -rp  "SMTP host (bijv. smtp.gmail.com): " SMTP_HOST
read -rp  "SMTP poort [587]: "                 SMTP_PORT;  [[ -z "$SMTP_PORT" ]] && SMTP_PORT="587"
read -rp  "SMTP gebruiker: "                   SMTP_USER
read -rsp "SMTP wachtwoord: "                  SMTP_PASSWORD; echo
read -rp  "Alert ontvanger (e-mailadres): "    ALERT_EMAIL_TO

echo ""
echo "─── Telegram alerts (leeg = uitgeschakeld) ──────────────────────"
read -rp "Telegram bot token: " TELEGRAM_BOT_TOKEN
read -rp "Telegram chat ID: "   TELEGRAM_CHAT_ID

cat > "$STAGING/app/.env" <<EOF
DB_PASSWORD=${DB_PASS}
SECRET_KEY=${SECRET_KEY}

SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_USER=${SMTP_USER}
SMTP_PASSWORD=${SMTP_PASSWORD}
ALERT_EMAIL_TO=${ALERT_EMAIL_TO}

TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}

DASHBOARD_API_URL=http://localhost:8000
DASHBOARD_API_TOKEN=
EOF
chmod 600 "$STAGING/app/.env"

# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════

install_docker_script='
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
apt-get install -y -qq python3 python3-pip cron
systemctl enable --now cron
'

start_stack_script="
pip3 install -q -r ${INSTALL_DIR}/alert/requirements.txt
cd ${INSTALL_DIR}/app
docker compose pull --quiet
docker compose up -d --remove-orphans
sleep 10
docker compose exec -T web python manage.py migrate --noinput 2>/dev/null || true
CRON_LINE='0 8 * * * ${INSTALL_DIR}/alert/cron.sh >> /var/log/domain-monitor-alert.log 2>&1'
(crontab -l 2>/dev/null | grep -v domain-monitor-alert; echo \"\$CRON_LINE\") | crontab -
"

# ════════════════════════════════════════════════════════════════════════════
# PROXMOX MODUS: LXC aanmaken en daarbinnen deployen
# ════════════════════════════════════════════════════════════════════════════

proxmox_deploy() {
    # Template zoeken en downloaden
    TEMPLATE=$(pveam list local 2>/dev/null | awk '/debian-12/{print $1; exit}')
    if [[ -z "$TEMPLATE" ]]; then
        log "Debian 12 template downloaden..."
        pveam update &>/dev/null
        TMPL_NAME=$(pveam available --section system 2>/dev/null | awk '/debian-12-standard/{print $2; exit}')
        [[ -z "$TMPL_NAME" ]] && die "Geen Debian 12 template gevonden. Voer 'pveam update' uit en probeer opnieuw."
        pveam download local "$TMPL_NAME"
        TEMPLATE="local:vztmpl/${TMPL_NAME}"
    fi
    log "Template: $TEMPLATE"

    # LXC aanmaken of bestaande hergebruiken
    if pct status "$VMID" &>/dev/null; then
        warn "LXC $VMID bestaat al — applicatie wordt bijgewerkt."
        pct start "$VMID" 2>/dev/null || true
    else
        log "LXC $VMID aanmaken..."
        pct create "$VMID" "$TEMPLATE" \
            --hostname "$LXC_NAME" \
            --cores 2 \
            --memory "$LXC_MEM" \
            --rootfs "${STORAGE}:20" \
            --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp" \
            --features "nesting=1" \
            --unprivileged 0 \
            --onboot 1
        pct start "$VMID"
    fi

    # Wachten op netwerk
    log "Wachten op netwerk in LXC $VMID..."
    for i in $(seq 1 30); do
        if pct exec "$VMID" -- ip -4 addr show eth0 2>/dev/null | grep -q "inet "; then break; fi
        sleep 2
    done

    # Docker installeren in LXC
    if ! pct exec "$VMID" -- command -v docker &>/dev/null; then
        log "Docker installeren in LXC $VMID..."
        pct exec "$VMID" -- bash -c "$install_docker_script"
    else
        log "Docker al aanwezig in LXC $VMID."
        pct exec "$VMID" -- bash -c "apt-get install -y -qq python3 python3-pip cron && systemctl enable --now cron"
    fi

    # Bestanden naar LXC kopiëren
    log "Bestanden kopiëren naar LXC $VMID..."
    pct exec "$VMID" -- mkdir -p \
        "${INSTALL_DIR}/app" "${INSTALL_DIR}/alert" \
        "${INSTALL_DIR}/config" "${INSTALL_DIR}/ui/templates"

    push() { pct push "$VMID" "$1" "$2"; }
    push "$STAGING/app/docker-compose.yml"        "${INSTALL_DIR}/app/docker-compose.yml"
    push "$STAGING/app/.env"                      "${INSTALL_DIR}/app/.env"
    push "$STAGING/alert/alert.py"                "${INSTALL_DIR}/alert/alert.py"
    push "$STAGING/alert/cron.sh"                 "${INSTALL_DIR}/alert/cron.sh"
    push "$STAGING/alert/requirements.txt"        "${INSTALL_DIR}/alert/requirements.txt"
    push "$STAGING/ui/requirements.txt"           "${INSTALL_DIR}/ui/requirements.txt"
    push "$STAGING/ui/main.py"                    "${INSTALL_DIR}/ui/main.py"
    push "$STAGING/ui/templates/index.html"       "${INSTALL_DIR}/ui/templates/index.html"
    push "$STAGING/config/domains.txt"            "${INSTALL_DIR}/config/domains.txt"
    pct exec "$VMID" -- chmod 600 "${INSTALL_DIR}/app/.env"
    pct exec "$VMID" -- chmod +x  "${INSTALL_DIR}/alert/cron.sh"

    # Stack starten in LXC
    log "Stack starten in LXC $VMID..."
    pct exec "$VMID" -- bash -c "$start_stack_script"

    LXC_IP=$(pct exec "$VMID" -- ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    print_summary "$LXC_IP" "$VMID"
}

# ════════════════════════════════════════════════════════════════════════════
# DIRECTE MODUS: installeren op huidige host
# ════════════════════════════════════════════════════════════════════════════

direct_deploy() {
    if ! command -v docker &>/dev/null; then
        log "Docker installeren via get.docker.com..."
        bash -c "$install_docker_script"
    else
        log "Docker al aanwezig: $(docker --version)"
        apt-get install -y -qq python3 python3-pip cron
        systemctl enable --now cron
    fi

    log "Bestanden kopiëren naar $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR/app" "$INSTALL_DIR/alert" "$INSTALL_DIR/config" "$INSTALL_DIR/ui/templates"

    # Bestaand .env niet overschrijven
    if [[ -f "$INSTALL_DIR/app/.env" ]]; then
        warn ".env bestaat al — configuratie niet overschreven."
        cp "$STAGING/app/docker-compose.yml" "$INSTALL_DIR/app/"
    else
        cp -r "$STAGING/app/."    "$INSTALL_DIR/app/"
    fi
    cp -r "$STAGING/alert/."  "$INSTALL_DIR/alert/"
    cp -r "$STAGING/ui/."     "$INSTALL_DIR/ui/"
    [[ ! -f "$INSTALL_DIR/config/domains.txt" ]] && cp "$STAGING/config/domains.txt" "$INSTALL_DIR/config/"
    chmod 600 "$INSTALL_DIR/app/.env" 2>/dev/null || true
    chmod +x  "$INSTALL_DIR/alert/cron.sh"

    log "Stack starten..."
    bash -c "$start_stack_script"

    HOST_IP=$(hostname -I | awk '{print $1}')
    print_summary "$HOST_IP" ""
}

# ════════════════════════════════════════════════════════════════════════════

print_summary() {
    local IP="$1"
    local VMID_INFO="$2"
    echo ""
    echo "════════════════════════════════════════════════"
    echo -e "${GREEN}  Domain Monitor succesvol geïnstalleerd!${NC}"
    echo "════════════════════════════════════════════════"
    echo ""
    [[ -n "$VMID_INFO" ]] && echo "  LXC VMID  : $VMID_INFO"
    echo "  Overzicht : http://${IP}:3000   ← status dashboard"
    echo "  Dashboard : http://${IP}:8000   ← internet.nl details"
    echo "  Config    : ${INSTALL_DIR}/app/.env"
    echo ""
    echo "  Admin account aanmaken:"
    if [[ -n "$VMID_INFO" ]]; then
        echo "    pct exec $VMID_INFO -- bash -c 'cd ${INSTALL_DIR}/app && docker compose exec web python manage.py createsuperuser'"
    else
        echo "    cd ${INSTALL_DIR}/app && docker compose exec web python manage.py createsuperuser"
    fi
    echo ""
}

# ════════════════════════════════════════════════════════════════════════════
# Start
# ════════════════════════════════════════════════════════════════════════════

if [[ "$PROXMOX_MODE" -eq 1 ]]; then
    proxmox_deploy
else
    direct_deploy
fi
