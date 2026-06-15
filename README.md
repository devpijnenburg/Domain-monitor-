# Domain Monitor

Self-hosted domain monitoring tool vergelijkbaar met [internet.nl](https://internet.nl). Controleert TLS, DNSSEC, SPF, DKIM, DMARC, HSTS, IPv6 en meer. Alerteert via e-mail en/of Telegram bij verslechtering van scores.

## Stack

- **internet.nl Dashboard** — officiële open-source implementatie van internet.nl checks
- **PostgreSQL + Redis + Celery** — database, cache, taakwachtrij
- **Proxmox LXC** (Ubuntu 22.04, 4 vCPU, 4 GB RAM, 40 GB disk)
- **GitHub Actions** — CI/CD pipeline voor deployment

## GitHub Secrets instellen

Voeg de volgende secrets toe in je GitHub repository (Settings → Secrets and variables → Actions):

| Secret               | Beschrijving                                        |
|----------------------|-----------------------------------------------------|
| `PROXMOX_HOST`       | IP-adres of hostname van je Proxmox server          |
| `PROXMOX_SSH_KEY`    | Private SSH key voor `root@PROXMOX_HOST`            |
| `LXC_VMID`           | Container ID (bijv. `200`)                          |
| `SMTP_HOST`          | SMTP-server (bijv. `smtp.gmail.com`)                |
| `SMTP_PORT`          | SMTP-poort (bijv. `587`)                            |
| `SMTP_USER`          | SMTP-gebruikersnaam                                 |
| `SMTP_PASSWORD`      | SMTP-wachtwoord                                     |
| `ALERT_EMAIL_TO`     | E-mailadres voor alerts                             |
| `TELEGRAM_BOT_TOKEN` | Token van Telegram bot (optioneel)                  |
| `TELEGRAM_CHAT_ID`   | Chat-ID voor Telegram berichten (optioneel)         |

> SMTP en Telegram zijn beide optioneel. Als de secrets leeg zijn, wordt dat kanaal overgeslagen.

## SSH-toegang instellen

Zorg dat de publieke sleutel die bij `PROXMOX_SSH_KEY` hoort in `/root/.ssh/authorized_keys` staat op de Proxmox host.

## Domeinen configureren

Bewerk `config/domains.txt` en voeg je domeinen toe (één per regel):

```
mijndomein.nl
ander-domein.nl
```

Commit en push naar `main` — de pipeline rolt automatisch uit.

## Na deployment

1. Open `http://<LXC_IP>:8000` voor het Dashboard
2. Maak een admin-account aan:
   ```bash
   pct exec <LXC_VMID> -- bash -c 'cd /opt/domain-monitor/app && docker compose exec web python manage.py createsuperuser'
   ```
3. Log in, voeg je domeinen toe en plan een scan

## Alerting

Het script `alert/alert.py` draait dagelijks om 08:00 via cron. Het:
- Vergelijkt de laatste scan met de vorige meting
- Alerteert als totaalscore ≥ 5% daalt
- Alerteert als een kritieke check (DNSSEC, certificaat, HTTPS) faalt

Handmatig uitvoeren:
```bash
pct exec <LXC_VMID> -- python3 /opt/domain-monitor/alert/alert.py
```

## Opnieuw deployen

Elke push naar `main` triggert een nieuwe deployment. De LXC container wordt **niet** opnieuw aangemaakt als deze al bestaat — alleen de applicatie wordt bijgewerkt.
