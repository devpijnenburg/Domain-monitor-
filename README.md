# Domain Monitor

Self-hosted domain monitoring vergelijkbaar met [internet.nl](https://internet.nl). Controleert TLS, DNSSEC, SPF, DKIM, DMARC, HSTS, IPv6 en meer. Alerteert via e-mail en/of Telegram bij verslechtering van scores.

## Installatie

Voer uit op Ubuntu 22.04 / Debian 12 (LXC, VM of bare metal) als root:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/devpijnenburg/Domain-monitor-/main/install.sh)"
```

Het script installeert Docker automatisch indien afwezig, vraagt om SMTP en/of Telegram configuratie, en start de volledige stack.

## Na installatie

| URL | Wat |
|---|---|
| `http://<host>:3000` | Status dashboard — alle domeinen met score + check-iconen |
| `http://<host>:8000` | internet.nl Dashboard — volledige details en scanbeheer |

**Admin account aanmaken:**
```bash
cd /opt/domain-monitor/app
docker compose exec web python manage.py createsuperuser
```

**Alert handmatig testen:**
```bash
python3 /opt/domain-monitor/alert/alert.py
```

## Configuratie

Alle instellingen staan in `/opt/domain-monitor/app/.env`. Bewerk dit bestand om SMTP of Telegram aan/uit te zetten.

## Stack

| Service | Beschrijving | Poort |
|---|---|---|
| **internet.nl Dashboard** | Officiële open-source implementatie van internet.nl checks | 8000 |
| **Status dashboard** | Eigen overzichtspagina — scores (groen/geel/rood) + check-iconen per domein | 3000 |
| **PostgreSQL 15** | Opslag van scanresultaten | — |
| **Redis 7** | Cache en taakwachtrij | — |
| **Celery worker + beat** | Achtergrondscans en scheduler | — |
| **alert.py** | Dagelijkse cron — alerteert bij score-daling ≥ 5% of kritieke check-falen | — |

## Updates

Voer het installatiescript opnieuw uit — het is idempotent en overschrijft alleen de applicatiebestanden:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/devpijnenburg/Domain-monitor-/main/install.sh)"
```
