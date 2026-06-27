#!/usr/bin/env bash
# Domain Monitor — one-liner installer
# bash -c "$(curl -fsSL https://raw.githubusercontent.com/devpijnenburg/Domain-monitor-/main/install.sh)"
set -euo pipefail

INSTALL_DIR="/opt/domain-monitor"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${BLUE}[…]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# tr | head geeft SIGPIPE — gebruik subshell zonder pipefail
randstr() { local n=$1 c=${2:-A-Za-z0-9}; (set +o pipefail; tr -dc "$c" </dev/urandom | head -c "$n"); }

[[ $EUID -ne 0 ]] && die "Voer dit script uit als root."

# ════════════════════════════════════════════════════════════════════════════
# Staging: alle bestanden als heredoc schrijven
# ════════════════════════════════════════════════════════════════════════════

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT
mkdir -p "$STAGING/app" "$STAGING/alert" "$STAGING/config" \
         "$STAGING/ui/templates" "$STAGING/monitor"

# ── docker-compose.yml ──────────────────────────────────────────────────────
cat > "$STAGING/app/docker-compose.yml" <<'COMPOSE'
services:
  monitor:
    image: python:3.12-slim
    restart: unless-stopped
    volumes:
      - ../monitor:/app
      - data:/data
    environment:
      DOMAINS_FILE: /data/domains.txt
      RESULTS_FILE: /data/results.json
      SCAN_INTERVAL_HOURS: "24"
    command: >
      sh -c "pip install --quiet --break-system-packages -r /app/requirements.txt &&
             python /app/checker.py"

  ui:
    image: python:3.12-slim
    restart: unless-stopped
    working_dir: /app
    volumes:
      - ../ui:/app
      - data:/data
    ports:
      - "3000:3000"
    environment:
      RESULTS_FILE: /data/results.json
    command: >
      sh -c "pip install --quiet --break-system-packages -r /app/requirements.txt &&
             uvicorn main:app --host 0.0.0.0 --port 3000"

volumes:
  data:
COMPOSE

# ── monitor/checker.py ──────────────────────────────────────────────────────
cat > "$STAGING/monitor/checker.py" <<'CHECKEREOF'
#!/usr/bin/env python3
import json, os, socket, ssl, time
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import requests
import checkdmarc

DOMAINS_FILE = os.getenv("DOMAINS_FILE", "/data/domains.txt")
RESULTS_FILE = os.getenv("RESULTS_FILE", "/data/results.json")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL_HOURS", "24")) * 3600

CHECK_WEIGHTS = {"https": 20, "tls_cert": 20, "hsts": 10, "ipv6": 10, "dnssec": 15, "spf": 10, "dmarc": 15}

def check_https(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=10, allow_redirects=True)
        return {"status": "passed", "detail": f"HTTP {r.status_code}"}
    except requests.exceptions.SSLError as e:
        return {"status": "failed", "detail": f"SSL fout: {str(e)[:80]}"}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}

def check_tls_cert(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        if days < 0:
            return {"status": "failed", "detail": "Certificaat verlopen"}
        if days < 14:
            return {"status": "warning", "detail": f"Verloopt over {days} dagen"}
        return {"status": "passed", "detail": f"Geldig, nog {days} dagen"}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}

def check_hsts(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=10, allow_redirects=False)
        hsts = r.headers.get("Strict-Transport-Security", "")
        if not hsts:
            return {"status": "failed", "detail": "HSTS header ontbreekt"}
        return {"status": "passed", "detail": hsts[:80]} if "max-age" in hsts else {"status": "warning", "detail": hsts[:80]}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}

def check_ipv6(domain):
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET6)
        return {"status": "passed", "detail": results[0][4][0]} if results else {"status": "failed", "detail": "Geen AAAA record"}
    except socket.gaierror:
        return {"status": "failed", "detail": "Geen AAAA record"}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}

def check_dnssec(domain):
    try:
        ds = dns.resolver.resolve(domain, "DS", raise_on_no_answer=False)
        if ds.rrset:
            return {"status": "passed", "detail": "DS record aanwezig"}
        dnskey = dns.resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        if dnskey.rrset:
            return {"status": "warning", "detail": "DNSKEY aanwezig maar geen DS"}
        return {"status": "failed", "detail": "Geen DNSSEC records"}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}

def check_spf(domain):
    try:
        result = checkdmarc.check_spf(domain)
        if result.get("valid"):
            return {"status": "passed", "detail": (result.get("record") or "")[:80]}
        return {"status": "failed", "detail": (result.get("error") or "Geen SPF record")[:80]}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}

def check_dmarc(domain):
    try:
        result = checkdmarc.check_dmarc(domain)
        if result.get("valid"):
            policy = (result.get("tags") or {}).get("p", {}).get("value", "?")
            return {"status": "passed", "detail": f"policy={policy}"}
        return {"status": "failed", "detail": (result.get("error") or "Geen DMARC record")[:80]}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}

def compute_score(checks):
    total = sum(CHECK_WEIGHTS.values())
    earned = sum(w for k, w in CHECK_WEIGHTS.items() if checks.get(k, {}).get("status") == "passed")
    earned += sum(w / 2 for k, w in CHECK_WEIGHTS.items() if checks.get(k, {}).get("status") == "warning")
    return round(earned / total * 100)

def scan_domain(domain):
    print(f"  {domain} ...", flush=True)
    checks = {
        "https": check_https(domain), "tls_cert": check_tls_cert(domain),
        "hsts": check_hsts(domain), "ipv6": check_ipv6(domain),
        "dnssec": check_dnssec(domain), "spf": check_spf(domain), "dmarc": check_dmarc(domain),
    }
    score = compute_score(checks)
    print(f"    → {score}%", flush=True)
    return {"checks": checks, "total_score": score}

def load_domains():
    p = Path(DOMAINS_FILE)
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]

def run_scan():
    domains = load_domains()
    if not domains:
        print(f"Geen domeinen in {DOMAINS_FILE}. Voeg domeinen toe en herstart de container.", flush=True)
        return
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M')}] Scannen van {len(domains)} domein(en)...", flush=True)
    results = {}
    for domain in domains:
        try:
            results[domain] = scan_domain(domain)
        except Exception as e:
            print(f"  FOUT bij {domain}: {e}", flush=True)
            results[domain] = {"checks": {}, "total_score": None}
    output = {"scan_date": datetime.now(timezone.utc).isoformat(), "results": results}
    Path(RESULTS_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(RESULTS_FILE).write_text(json.dumps(output, indent=2))
    print(f"Resultaten opgeslagen: {RESULTS_FILE}", flush=True)

if __name__ == "__main__":
    while True:
        run_scan()
        print(f"Volgende scan over {SCAN_INTERVAL // 3600} uur...", flush=True)
        time.sleep(SCAN_INTERVAL)
CHECKEREOF

cat > "$STAGING/monitor/requirements.txt" <<'MONREQEOF'
requests>=2.31.0
dnspython>=2.6.0
checkdmarc>=5.0.0
MONREQEOF

# ── ui/main.py ──────────────────────────────────────────────────────────────
cat > "$STAGING/ui/main.py" <<'UIMAINEOF'
import json, os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
RESULTS_FILE = os.getenv("RESULTS_FILE", "/data/results.json")

CHECKS = [("https","HTTPS"),("tls_cert","Cert"),("hsts","HSTS"),("ipv6","IPv6"),("dnssec","DNSSEC"),("spf","SPF"),("dmarc","DMARC")]

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
    domains, scan_date = [], ""
    try:
        data = load_results()
        if data is None:
            error = f"Nog geen scanresultaten. De monitor-service voert de eerste scan uit bij opstart."
        else:
            scan_date = data.get("scan_date", "")
            for name, result in data.get("results", {}).items():
                checks_raw = result.get("checks", {})
                check_statuses = [{"key": k, "label": l, "status": checks_raw.get(k, {}).get("status", "not_tested"), "detail": checks_raw.get(k, {}).get("detail", "")} for k, l in CHECKS]
                domains.append({"name": name, "score": result.get("total_score"), "checks": check_statuses})
            domains.sort(key=lambda d: (d["score"] is None, -(d["score"] or 0)))
    except Exception as exc:
        error = f"Fout bij laden resultaten: {exc}"
    return templates.TemplateResponse(request, "index.html", context={"domains": domains, "scan_date": scan_date, "error": error, "check_labels": [l for _, l in CHECKS]})
UIMAINEOF

cat > "$STAGING/ui/requirements.txt" <<'UIREQEOF'
fastapi>=0.111.0
uvicorn[standard]>=0.29.0
jinja2>=3.1.4
UIREQEOF

cat > "$STAGING/ui/templates/index.html" <<'UIHTMLEOF'
<!DOCTYPE html>
<html lang="nl">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="60"><title>Domain Monitor</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;padding:2rem 1rem}
    header{max-width:1200px;margin:0 auto 2rem;display:flex;align-items:baseline;gap:1.5rem;flex-wrap:wrap}
    h1{font-size:1.6rem;font-weight:700;color:#f1f5f9}
    .meta{font-size:.8rem;color:#64748b}
    .refresh-note{margin-left:auto;font-size:.75rem;color:#475569}
    .error{max-width:1200px;margin:0 auto 1.5rem;background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1rem 1.25rem;color:#94a3b8;font-size:.9rem}
    .card{max-width:1200px;margin:0 auto;background:#1e293b;border-radius:12px;overflow:hidden;border:1px solid #334155}
    table{width:100%;border-collapse:collapse}
    thead tr{background:#0f172a;border-bottom:1px solid #334155}
    th{padding:.75rem 1rem;font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#64748b;text-align:left}
    th.c,td.c{text-align:center}
    tbody tr{border-bottom:1px solid #0f172a;transition:background .15s}
    tbody tr:last-child{border-bottom:none}
    tbody tr:hover{background:#263348}
    td{padding:.85rem 1rem;font-size:.9rem;vertical-align:middle}
    .dn{font-weight:600;color:#f1f5f9}
    .sc{display:inline-flex;align-items:center;justify-content:center;width:3.2rem;height:1.75rem;border-radius:6px;font-size:.8rem;font-weight:700}
    .sg{background:#14532d;color:#4ade80}.sy{background:#713f12;color:#fbbf24}.sr{background:#450a0a;color:#f87171}.sn{background:#1e293b;color:#475569;border:1px solid #334155}
    .ck{display:inline-flex;align-items:center;justify-content:center;width:1.6rem;height:1.6rem;border-radius:50%;font-size:.75rem;font-weight:700;cursor:default}
    .cp{background:#14532d;color:#4ade80}.cf{background:#450a0a;color:#f87171}.cw{background:#713f12;color:#fbbf24}.co{background:#1e293b;color:#475569;border:1px solid #334155}
    .empty{text-align:center;padding:3rem;color:#475569}
    @media(max-width:750px){.hm{display:none}}
  </style>
</head>
<body>
<header>
  <h1>Domain Monitor</h1>
  {% if scan_date %}<span class="meta">Laatste scan: {{ scan_date[:16]|replace("T"," ") }} UTC</span>{% endif %}
  <span class="refresh-note">Vernieuwt elke 60s</span>
</header>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<div class="card">
  {% if domains %}
  <table>
    <thead><tr><th>Domein</th><th class="c">Score</th>{% for l in check_labels %}<th class="c hm">{{ l }}</th>{% endfor %}</tr></thead>
    <tbody>{% for d in domains %}<tr>
      <td class="dn">{{ d.name }}</td>
      <td class="c">{% if d.score is not none %}{% if d.score>=80 %}<span class="sc sg">{{ d.score }}%</span>{% elif d.score>=60 %}<span class="sc sy">{{ d.score }}%</span>{% else %}<span class="sc sr">{{ d.score }}%</span>{% endif %}{% else %}<span class="sc sn">–</span>{% endif %}</td>
      {% for ch in d.checks %}<td class="c hm">{% if ch.status=="passed" %}<span class="ck cp" title="{{ ch.label }}: {{ ch.detail }}">✓</span>{% elif ch.status=="failed" %}<span class="ck cf" title="{{ ch.label }}: {{ ch.detail }}">✗</span>{% elif ch.status=="warning" %}<span class="ck cw" title="{{ ch.label }}: {{ ch.detail }}">!</span>{% else %}<span class="ck co" title="{{ ch.label }}: niet getest">–</span>{% endif %}</td>{% endfor %}
    </tr>{% endfor %}</tbody>
  </table>
  {% elif not error %}
  <div class="empty">Wachten op eerste scan...<br><small>De monitor voert elke 24 uur een scan uit.</small></div>
  {% endif %}
</div>
</body></html>
UIHTMLEOF

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
    return {d: {"total_score": r.get("total_score"), "checks": {k: v.get("status") for k, v in r.get("checks", {}).items()}} for d, r in data.get("results", {}).items()}

def load_previous_scores():
    return json.loads(SCORES_FILE.read_text()) if SCORES_FILE.exists() else {}

def detect_degradations(current, previous):
    issues = []
    for domain, cur in current.items():
        prev = previous.get(domain, {})
        domain_issues = []
        cs, ps = cur.get("total_score"), prev.get("total_score")
        if cs is not None and ps is not None and (ps - cs) >= DEGRADATION_THRESHOLD:
            domain_issues.append(f"Score gedaald {ps-cs:.0f}% ({ps:.0f}% → {cs:.0f}%)")
        for check in CRITICAL_CHECKS:
            if cur.get("checks", {}).get(check) in ("failed","error") and prev.get("checks", {}).get(check) not in ("failed","error"):
                domain_issues.append(f"Kritieke check mislukt: {check}")
        if domain_issues:
            issues.append({"domain": domain, "issues": domain_issues, "score": cs})
    return issues

def format_message(degradations):
    lines = [f"Domain Monitor Alert — {datetime.now().strftime('%Y-%m-%d %H:%M')}", f"{len(degradations)} domein(en) met verslechtering:\n"]
    for item in degradations:
        lines.append(f"  {item['domain']} (score: {item['score']}%)")
        for issue in item["issues"]:
            lines.append(f"    - {issue}")
    return "\n".join(lines)

def send_email(message, env):
    host = env.get("SMTP_HOST","")
    if not host: return
    to_addr = env.get("ALERT_EMAIL_TO","")
    if not to_addr: return
    msg = MIMEText(message)
    msg["Subject"] = "Domain Monitor: verslechtering gedetecteerd"
    msg["From"] = env.get("SMTP_USER","")
    msg["To"] = to_addr
    with smtplib.SMTP(host, int(env.get("SMTP_PORT",587))) as smtp:
        smtp.starttls()
        if env.get("SMTP_USER") and env.get("SMTP_PASSWORD"):
            smtp.login(env["SMTP_USER"], env["SMTP_PASSWORD"])
        smtp.send_message(msg)
    print(f"E-mail verstuurd naar {to_addr}")

def send_telegram(message, env):
    token, chat_id = env.get("TELEGRAM_BOT_TOKEN",""), env.get("TELEGRAM_CHAT_ID","")
    if not token or not chat_id: return
    requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json={"chat_id": chat_id, "text": message}, timeout=15).raise_for_status()
    print(f"Telegram bericht verstuurd naar {chat_id}")

def main():
    env = load_env()
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
            try: fn(message, env)
            except Exception as exc: print(f"Waarschuwing: {exc}", file=sys.stderr)
    else:
        print(f"Alle {len(current)} domeinen OK.")
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
REQEOF

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
    read -rp "LXC VMID [200]: "               VMID;     [[ -z "$VMID" ]]     && VMID=200
    read -rp "LXC naam [domain-monitor]: "    LXC_NAME; [[ -z "$LXC_NAME" ]] && LXC_NAME="domain-monitor"
    read -rp "Netwerk bridge [vmbr0]: "       BRIDGE;   [[ -z "$BRIDGE" ]]   && BRIDGE="vmbr0"
    read -rp "Geheugen MB [2048]: "           LXC_MEM;  [[ -z "$LXC_MEM" ]]  && LXC_MEM=2048
    read -rp "Opslag pool [local-lvm]: "      STORAGE;  [[ -z "$STORAGE" ]]  && STORAGE="local-lvm"
    PROXMOX_MODE=1
else
    PROXMOX_MODE=0
fi

echo ""
log "Configuratie invullen..."
echo ""

read -rp "Database wachtwoord (Enter = willekeurig): " DB_PASS
[[ -z "$DB_PASS" ]] && DB_PASS=$(randstr 32)
SECRET_KEY=$(randstr 60 'A-Za-z0-9@#%^&')

echo ""
echo "─── SMTP e-mail alerts (leeg = uitgeschakeld) ───────────────────"
read -rp  "SMTP host (bijv. smtp.gmail.com): " SMTP_HOST
read -rp  "SMTP poort [587]: "                 SMTP_PORT; [[ -z "$SMTP_PORT" ]] && SMTP_PORT="587"
read -rp  "SMTP gebruiker: "                   SMTP_USER
read -rsp "SMTP wachtwoord: "                  SMTP_PASSWORD; echo
read -rp  "Alert ontvanger (e-mailadres): "    ALERT_EMAIL_TO

echo ""
echo "─── Telegram alerts (leeg = uitgeschakeld) ──────────────────────"
read -rp "Telegram bot token: " TELEGRAM_BOT_TOKEN
read -rp "Telegram chat ID: "   TELEGRAM_CHAT_ID

cat > "$STAGING/app/.env" <<EOF
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_USER=${SMTP_USER}
SMTP_PASSWORD=${SMTP_PASSWORD}
ALERT_EMAIL_TO=${ALERT_EMAIL_TO}
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}
EOF
chmod 600 "$STAGING/app/.env"

# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════

install_docker_script='
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl python3 python3-pip cron
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
systemctl enable --now cron
'

start_stack_script="
cd ${INSTALL_DIR}/app
docker compose pull
docker compose up -d --remove-orphans
"

# ════════════════════════════════════════════════════════════════════════════
# PROXMOX MODUS
# ════════════════════════════════════════════════════════════════════════════

proxmox_deploy() {
    echo ""
    echo "════════════════════════════════════════════════"
    info "Stap 1/5 — LXC template voorbereiden"
    echo "════════════════════════════════════════════════"

    TEMPLATE=$(pveam list local 2>/dev/null | awk '/debian-12/{print $1; exit}')
    if [[ -z "$TEMPLATE" ]]; then
        info "Debian 12 template lijst ophalen..."
        pveam update
        TMPL_NAME=$(pveam available --section system 2>/dev/null | awk '/debian-12-standard/{print $2; exit}')
        [[ -z "$TMPL_NAME" ]] && die "Geen Debian 12 template gevonden. Voer 'pveam update' uit."
        info "Template downloaden: $TMPL_NAME"
        pveam download local "$TMPL_NAME"
        TEMPLATE="local:vztmpl/${TMPL_NAME}"
    fi
    log "Template: $TEMPLATE"

    echo ""
    echo "════════════════════════════════════════════════"
    info "Stap 2/5 — LXC container aanmaken"
    echo "════════════════════════════════════════════════"

    if pct status "$VMID" &>/dev/null; then
        warn "LXC $VMID bestaat al — applicatie wordt bijgewerkt."
        pct start "$VMID" 2>/dev/null || true
    else
        info "LXC $VMID aanmaken (${LXC_NAME}, ${LXC_MEM}MB RAM)..."
        pct create "$VMID" "$TEMPLATE" \
            --hostname "$LXC_NAME" --cores 2 --memory "$LXC_MEM" \
            --rootfs "${STORAGE}:20" --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp" \
            --features "nesting=1" --unprivileged 0 --onboot 1
        info "LXC starten..."
        pct start "$VMID"
        log "LXC $VMID gestart."
    fi

    info "Wachten op netwerk..."
    for i in $(seq 1 30); do
        pct exec "$VMID" -- ip -4 addr show eth0 2>/dev/null | grep -q "inet " && { log "Netwerk beschikbaar."; break; }
        echo -n "." ; sleep 2
    done; echo ""

    echo ""
    echo "════════════════════════════════════════════════"
    info "Stap 3/5 — Docker installeren in LXC"
    echo "════════════════════════════════════════════════"

    if ! pct exec "$VMID" -- command -v docker &>/dev/null; then
        info "Docker installeren (duurt ~1-2 minuten)..."
        pct exec "$VMID" -- bash -c "$install_docker_script"
        log "Docker geïnstalleerd."
    else
        log "Docker al aanwezig."
        pct exec "$VMID" -- bash -c "apt-get install -y -qq python3 python3-pip cron && systemctl enable --now cron"
    fi

    echo ""
    echo "════════════════════════════════════════════════"
    info "Stap 4/5 — Bestanden kopiëren naar LXC"
    echo "════════════════════════════════════════════════"

    pct exec "$VMID" -- mkdir -p \
        "${INSTALL_DIR}/app" "${INSTALL_DIR}/alert" "${INSTALL_DIR}/config" \
        "${INSTALL_DIR}/monitor" "${INSTALL_DIR}/ui/templates"

    push() { info "  → $2"; pct push "$VMID" "$1" "$2"; }
    push "$STAGING/app/docker-compose.yml"       "${INSTALL_DIR}/app/docker-compose.yml"
    push "$STAGING/app/.env"                     "${INSTALL_DIR}/app/.env"
    push "$STAGING/monitor/checker.py"           "${INSTALL_DIR}/monitor/checker.py"
    push "$STAGING/monitor/requirements.txt"     "${INSTALL_DIR}/monitor/requirements.txt"
    push "$STAGING/ui/main.py"                   "${INSTALL_DIR}/ui/main.py"
    push "$STAGING/ui/requirements.txt"          "${INSTALL_DIR}/ui/requirements.txt"
    push "$STAGING/ui/templates/index.html"      "${INSTALL_DIR}/ui/templates/index.html"
    push "$STAGING/alert/alert.py"               "${INSTALL_DIR}/alert/alert.py"
    push "$STAGING/alert/cron.sh"                "${INSTALL_DIR}/alert/cron.sh"
    push "$STAGING/alert/requirements.txt"       "${INSTALL_DIR}/alert/requirements.txt"
    push "$STAGING/config/domains.txt"           "${INSTALL_DIR}/config/domains.txt"

    pct exec "$VMID" -- chmod 600 "${INSTALL_DIR}/app/.env"
    pct exec "$VMID" -- chmod +x  "${INSTALL_DIR}/alert/cron.sh"

    # Domeinen-bestand ook in het Docker data-volume zetten
    pct exec "$VMID" -- bash -c "mkdir -p ${INSTALL_DIR}/data && cp ${INSTALL_DIR}/config/domains.txt ${INSTALL_DIR}/data/domains.txt"

    # Alert dependencies op LXC-systeem
    pct exec "$VMID" -- pip3 install --quiet --break-system-packages -r "${INSTALL_DIR}/alert/requirements.txt"

    # Cron
    CRON_LINE="0 8 * * * ${INSTALL_DIR}/alert/cron.sh >> /var/log/domain-monitor-alert.log 2>&1"
    pct exec "$VMID" -- bash -c "(crontab -l 2>/dev/null | grep -v domain-monitor-alert; echo \"$CRON_LINE\") | crontab -"

    log "Bestanden gekopieerd en cron ingesteld."

    echo ""
    echo "════════════════════════════════════════════════"
    info "Stap 5/5 — Docker Compose stack starten"
    echo "════════════════════════════════════════════════"

    info "Images downloaden en containers starten..."
    pct exec "$VMID" -- bash -c "$start_stack_script"
    log "Stack gestart."

    LXC_IP=$(pct exec "$VMID" -- ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    print_summary "$LXC_IP" "$VMID"
}

# ════════════════════════════════════════════════════════════════════════════
# DIRECTE MODUS
# ════════════════════════════════════════════════════════════════════════════

direct_deploy() {
    if ! command -v docker &>/dev/null; then
        info "Docker installeren..."
        bash -c "$install_docker_script"
    else
        log "Docker al aanwezig: $(docker --version)"
        apt-get install -y -qq python3 python3-pip cron
        systemctl enable --now cron
    fi

    mkdir -p "$INSTALL_DIR/app" "$INSTALL_DIR/alert" "$INSTALL_DIR/config" \
             "$INSTALL_DIR/monitor" "$INSTALL_DIR/ui/templates" "$INSTALL_DIR/data"

    [[ -f "$INSTALL_DIR/app/.env" ]] && { warn ".env bestaat al — niet overschreven."; cp "$STAGING/app/docker-compose.yml" "$INSTALL_DIR/app/"; } || cp -r "$STAGING/app/." "$INSTALL_DIR/app/"
    cp -r "$STAGING/monitor/." "$INSTALL_DIR/monitor/"
    cp -r "$STAGING/ui/."      "$INSTALL_DIR/ui/"
    cp -r "$STAGING/alert/."   "$INSTALL_DIR/alert/"
    [[ ! -f "$INSTALL_DIR/config/domains.txt" ]] && cp "$STAGING/config/domains.txt" "$INSTALL_DIR/config/"
    cp "$INSTALL_DIR/config/domains.txt" "$INSTALL_DIR/data/domains.txt"
    chmod 600 "$INSTALL_DIR/app/.env" 2>/dev/null || true
    chmod +x  "$INSTALL_DIR/alert/cron.sh"
    pip3 install --quiet --break-system-packages -r "$INSTALL_DIR/alert/requirements.txt"
    CRON_LINE="0 8 * * * $INSTALL_DIR/alert/cron.sh >> /var/log/domain-monitor-alert.log 2>&1"
    (crontab -l 2>/dev/null | grep -v domain-monitor-alert; echo "$CRON_LINE") | crontab -

    bash -c "$start_stack_script"

    HOST_IP=$(hostname -I | awk '{print $1}')
    print_summary "$HOST_IP" ""
}

# ════════════════════════════════════════════════════════════════════════════

print_summary() {
    local IP="$1" VMID_INFO="$2"
    echo ""
    echo "════════════════════════════════════════════════"
    echo -e "${GREEN}  Domain Monitor succesvol geïnstalleerd!${NC}"
    echo "════════════════════════════════════════════════"
    echo ""
    [[ -n "$VMID_INFO" ]] && echo "  LXC VMID  : $VMID_INFO"
    echo "  Dashboard : http://${IP}:3000"
    echo "  Config    : ${INSTALL_DIR}/app/.env"
    echo ""
    echo "  Domeinen toevoegen:"
    if [[ -n "$VMID_INFO" ]]; then
        echo "    pct exec $VMID_INFO -- nano ${INSTALL_DIR}/data/domains.txt"
        echo "    pct exec $VMID_INFO -- docker compose -f ${INSTALL_DIR}/app/docker-compose.yml restart monitor"
    else
        echo "    nano ${INSTALL_DIR}/data/domains.txt"
        echo "    docker compose -f ${INSTALL_DIR}/app/docker-compose.yml restart monitor"
    fi
    echo ""
}

if [[ "$PROXMOX_MODE" -eq 1 ]]; then
    proxmox_deploy
else
    direct_deploy
fi
