#!/usr/bin/env bash
# Domain Monitor — one-liner installer
# bash -c "$(curl -fsSL https://raw.githubusercontent.com/devpijnenburg/Domain-monitor-/main/install.sh)"
set -euo pipefail

INSTALL_DIR="/opt/domain-monitor"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && die "Voer dit script uit als root: sudo bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/devpijnenburg/Domain-monitor-/main/install.sh)\""

# ── Docker ──────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    log "Docker installeren..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    log "Docker geïnstalleerd."
else
    log "Docker al aanwezig: $(docker --version)"
fi

# ── Python + cron ────────────────────────────────────────────────────────────
apt-get install -y -qq python3 python3-pip cron
systemctl enable --now cron

# ── Mappen ──────────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR/app" "$INSTALL_DIR/alert" "$INSTALL_DIR/config"

# ── docker-compose.yml ──────────────────────────────────────────────────────
cat > "$INSTALL_DIR/app/docker-compose.yml" <<'COMPOSE'
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

volumes:
  db_data:
  redis_data:
  app_data:
COMPOSE

# ── alert.py ────────────────────────────────────────────────────────────────
cat > "$INSTALL_DIR/alert/alert.py" <<'PYEOF'
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

# ── cron.sh ─────────────────────────────────────────────────────────────────
cat > "$INSTALL_DIR/alert/cron.sh" <<'CRONEOF'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec python3 alert.py
CRONEOF
chmod +x "$INSTALL_DIR/alert/cron.sh"

# ── requirements.txt ────────────────────────────────────────────────────────
cat > "$INSTALL_DIR/alert/requirements.txt" <<'REQEOF'
requests>=2.31.0
python-telegram-bot>=20.0
REQEOF

# ── Domeinen ────────────────────────────────────────────────────────────────
if [[ ! -f "$INSTALL_DIR/config/domains.txt" ]]; then
    cat > "$INSTALL_DIR/config/domains.txt" <<'DOMEOF'
# Voeg hier je domeinen toe, één per regel
# example.com
DOMEOF
fi

# ── .env configureren ───────────────────────────────────────────────────────
ENV_FILE="$INSTALL_DIR/app/.env"

if [[ -f "$ENV_FILE" ]]; then
    warn ".env bestaat al — configuratie wordt niet overschreven."
    warn "Bewerk handmatig: $ENV_FILE"
else
    echo ""
    log "Configuratie invullen..."
    echo ""

    read -rp "Database wachtwoord (Enter = willekeurig): " DB_PASS
    [[ -z "$DB_PASS" ]] && DB_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
    SECRET_KEY=$(tr -dc 'A-Za-z0-9!@#%^&*' </dev/urandom | head -c 60)

    echo ""
    echo "─── SMTP e-mail alerts (leeg = uitgeschakeld) ───────────────────"
    read -rp  "SMTP host (bijv. smtp.gmail.com): " SMTP_HOST
    read -rp  "SMTP poort [587]: "                 SMTP_PORT
    [[ -z "$SMTP_PORT" ]] && SMTP_PORT="587"
    read -rp  "SMTP gebruiker: "                   SMTP_USER
    read -rsp "SMTP wachtwoord: "                  SMTP_PASSWORD; echo
    read -rp  "Alert ontvanger (e-mailadres): "    ALERT_EMAIL_TO

    echo ""
    echo "─── Telegram alerts (leeg = uitgeschakeld) ──────────────────────"
    read -rp "Telegram bot token: " TELEGRAM_BOT_TOKEN
    read -rp "Telegram chat ID: "   TELEGRAM_CHAT_ID

    cat > "$ENV_FILE" <<EOF
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
    chmod 600 "$ENV_FILE"
    log ".env aangemaakt."
fi

# ── Python dependencies ──────────────────────────────────────────────────────
log "Python-afhankelijkheden installeren..."
pip3 install -q -r "$INSTALL_DIR/alert/requirements.txt"

# ── Stack starten ────────────────────────────────────────────────────────────
log "Docker Compose stack starten..."
cd "$INSTALL_DIR/app"
docker compose pull --quiet
docker compose up -d --remove-orphans

# ── Migraties ────────────────────────────────────────────────────────────────
log "Wachten op database..."
sleep 8
docker compose exec -T web python manage.py migrate --noinput 2>/dev/null || \
    warn "Migraties later uitvoeren: cd $INSTALL_DIR/app && docker compose exec web python manage.py migrate"

# ── Cron ─────────────────────────────────────────────────────────────────────
CRON_LINE="0 8 * * * $INSTALL_DIR/alert/cron.sh >> /var/log/domain-monitor-alert.log 2>&1"
(crontab -l 2>/dev/null | grep -v "domain-monitor-alert"; echo "$CRON_LINE") | crontab -
log "Cron ingesteld (dagelijks 08:00)."

# ── Klaar ─────────────────────────────────────────────────────────────────────
HOST_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "════════════════════════════════════════════════"
echo -e "${GREEN}  Domain Monitor succesvol geïnstalleerd!${NC}"
echo "════════════════════════════════════════════════"
echo ""
echo "  Dashboard : http://${HOST_IP}:8000"
echo "  Config    : $INSTALL_DIR/app/.env"
echo "  Domeinen  : $INSTALL_DIR/config/domains.txt"
echo ""
echo "  Admin account aanmaken:"
echo "    cd $INSTALL_DIR/app"
echo "    docker compose exec web python manage.py createsuperuser"
echo ""
