#!/usr/bin/env bash
# install.sh — Domain Monitor installatiescript
# Vereisten: Ubuntu 22.04 / Debian 12, uitgevoerd als root of met sudo
set -euo pipefail

INSTALL_DIR="/opt/domain-monitor"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && die "Voer dit script uit als root: sudo $0"

# --- Docker installeren indien afwezig ---
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

# --- Python + pip ---
if ! command -v python3 &>/dev/null || ! python3 -m pip --version &>/dev/null 2>&1; then
    log "Python3 + pip installeren..."
    apt-get install -y -qq python3 python3-pip
fi

# --- Cron ---
apt-get install -y -qq cron
systemctl enable --now cron

# --- Installatiemap aanmaken ---
mkdir -p "$INSTALL_DIR/app" "$INSTALL_DIR/alert" "$INSTALL_DIR/config"

# --- Bestanden kopiëren ---
log "Bestanden kopiëren naar $INSTALL_DIR..."
cp "$SCRIPT_DIR/app/docker-compose.yml" "$INSTALL_DIR/app/"
cp "$SCRIPT_DIR/alert/alert.py"         "$INSTALL_DIR/alert/"
cp "$SCRIPT_DIR/alert/requirements.txt" "$INSTALL_DIR/alert/"
cp "$SCRIPT_DIR/alert/cron.sh"          "$INSTALL_DIR/alert/"
chmod +x "$INSTALL_DIR/alert/cron.sh"

# Domeinen kopiëren (niet overschrijven als al aanwezig)
if [[ ! -f "$INSTALL_DIR/config/domains.txt" ]]; then
    cp "$SCRIPT_DIR/config/domains.txt" "$INSTALL_DIR/config/"
fi

# --- .env configureren ---
ENV_FILE="$INSTALL_DIR/app/.env"

if [[ -f "$ENV_FILE" ]]; then
    warn ".env bestaat al — configuratie wordt niet overschreven."
    warn "Bewerk handmatig: $ENV_FILE"
else
    log "Configuratie invullen..."
    echo ""

    read -rp "Database wachtwoord (of Enter voor willekeurig): " DB_PASS
    [[ -z "$DB_PASS" ]] && DB_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)

    SECRET_KEY=$(tr -dc 'A-Za-z0-9!@#$%^&*' </dev/urandom | head -c 60)

    echo ""
    echo "--- SMTP e-mail alerts (leeg laten = uitschakelen) ---"
    read -rp "SMTP host (bijv. smtp.gmail.com): "   SMTP_HOST
    read -rp "SMTP poort [587]: "                   SMTP_PORT
    [[ -z "$SMTP_PORT" ]] && SMTP_PORT="587"
    read -rp "SMTP gebruiker: "                     SMTP_USER
    read -rsp "SMTP wachtwoord: "                   SMTP_PASSWORD; echo
    read -rp "Alert e-mail ontvanger: "             ALERT_EMAIL_TO

    echo ""
    echo "--- Telegram alerts (leeg laten = uitschakelen) ---"
    read -rp "Telegram bot token: "  TELEGRAM_BOT_TOKEN
    read -rp "Telegram chat ID: "    TELEGRAM_CHAT_ID

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

# --- Alert dependencies ---
log "Python-afhankelijkheden installeren..."
pip3 install -q -r "$INSTALL_DIR/alert/requirements.txt"

# --- Docker Compose stack starten ---
log "Docker Compose stack starten..."
cd "$INSTALL_DIR/app"
docker compose pull --quiet
docker compose up -d --remove-orphans
log "Stack gestart."

# --- Database migraties uitvoeren ---
log "Database migraties uitvoeren..."
sleep 5  # wacht tot PostgreSQL klaar is
docker compose exec -T web python manage.py migrate --noinput 2>/dev/null || \
    warn "Migraties mislukt — probeer later handmatig: docker compose exec web python manage.py migrate"

# --- Cron job instellen (dagelijks 08:00) ---
CRON_LINE="0 8 * * * $INSTALL_DIR/alert/cron.sh >> /var/log/domain-monitor-alert.log 2>&1"
(crontab -l 2>/dev/null | grep -v "domain-monitor-alert"; echo "$CRON_LINE") | crontab -
log "Cron job ingesteld (dagelijks 08:00)."

# --- Samenvatting ---
HOST_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "=============================================="
echo -e "${GREEN}  Domain Monitor succesvol geïnstalleerd!${NC}"
echo "=============================================="
echo ""
echo "  Dashboard:  http://${HOST_IP}:8000"
echo "  Installatiemap: $INSTALL_DIR"
echo ""
echo "  Volgende stappen:"
echo "  1. Open http://${HOST_IP}:8000 in je browser"
echo "  2. Maak een admin account aan:"
echo "       cd $INSTALL_DIR/app && docker compose exec web python manage.py createsuperuser"
echo "  3. Voeg domeinen toe in: $INSTALL_DIR/config/domains.txt"
echo "  4. Alert test: python3 $INSTALL_DIR/alert/alert.py"
echo ""
