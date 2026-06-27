# Domain Monitor

Self-hosted domain monitoring tool vergelijkbaar met [internet.nl](https://internet.nl). Controleert TLS, DNSSEC, SPF, DKIM, DMARC, HSTS, IPv6 en meer. Alerteert via e-mail en/of Telegram bij verslechtering van scores.

## Installatie

Voer het installatiescript uit op een Ubuntu 22.04 / Debian 12 host (LXC, VM of bare metal):

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/devpijnenburg/Domain-monitor-/main/install.sh)"
```

Het script:
- Installeert Docker automatisch indien afwezig
- Vraagt om SMTP en/of Telegram configuratie
- Start de internet.nl Dashboard stack via Docker Compose
- Stelt een dagelijkse cron in voor degradation-alerts

## Na installatie

**Status overzicht (eigen dashboard):**
```
http://<host-ip>:3000
```

**internet.nl detail dashboard:**
```
http://<host-ip>:8000
```

**Admin account aanmaken:**
```bash
cd /opt/domain-monitor/app
docker compose exec web python manage.py createsuperuser
```

**Domeinen toevoegen:**
Bewerk `/opt/domain-monitor/config/domains.txt` (één domein per regel).

**Alert handmatig testen:**
```bash
python3 /opt/domain-monitor/alert/alert.py
```

## Configuratie

Na installatie staat de configuratie in `/opt/domain-monitor/app/.env`. Bewerk dit bestand om SMTP of Telegram aan/uit te zetten.

## Stack

- **internet.nl Dashboard** — officiële open-source implementatie van internet.nl checks
- **PostgreSQL + Redis + Celery** — database, cache, taakwachtrij
- **alert.py** — vergelijkt scores dagelijks, alerteert bij verslechtering ≥ 5% of falende kritieke check

## Updates

```bash
cd /pad/naar/domain-monitor-
git pull
sudo bash install.sh
```
