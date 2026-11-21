# homelab-cert

Self-hosted private CA for your homelab: one root CA, one certificate per server, expiry alerts via webhook or Telegram. Single static Rust binary in a `scratch` image.

## Run
```bash
cp .env.example .env     # set a real username and password
docker compose up -d --build
```
Open http://localhost:8765. Defaults if unset: `admin` / `changeme` (a warning is logged).

## Use
1. **Create the root CA**, then download the root certificate and trust it on your devices.
2. **New certificate** per server (name + extra DNS names/IPs). Download the zip: `.crt`, `.key`, `-fullchain.crt`, `root-ca.crt`.
3. **Notifications**: set a webhook URL and day thresholds. Telegram: `https://api.telegram.org/bot<token>` plus your chat ID.

Data (including private keys) lives in `homelab-cert.json` in the `homelab-cert-data` volume. Back it up and put the UI behind HTTPS (e.g. your reverse proxy).
