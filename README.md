# Honai

AI honeypot with agentic SOC analysis. A Cowrie SSH honeypot captures real
attacker sessions from the open internet, an AI agent triages each session and
assigns a verdict, and the system fires urgent alerts on critical activity plus
a periodic digest of everything else.

Built in 24 hours for a hackathon.

## Architecture

```
       internet
          │
          ▼  port 22
┌──────────────────┐
│ Cowrie (Docker)  │   on a Hetzner VPS; real SSH on :2222
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
└────┬─────────┬───┘
     │         │
     │         │ SELECT WHERE status='new'
     │         ▼
     │   ┌────────────────┐
     │   │ agents/  (Garv)│   AI triage → sets verdict + writes digest
     │   └────────┬───────┘
     │            │ UPDATE verdict, INSERT digests
     │            ▼
     │       sessions.db
     │
     │ SELECT verdict='critical' + latest digest
     ▼
┌──────────────────┐
│   notify/        │   Telegram
└──────────────────┘
```

## Layout

| Path           | Owner   | Purpose                                                  |
| -------------- | ------- | -------------------------------------------------------- |
| `honeypot/`    | Charlie | Cowrie `docker-compose.yml` + config                     |
| `ingest/`      | Charlie | Python tailer that turns `cowrie.json` into DB rows      |
| `db/`          | Charlie | Schema (`init.sql`) and any migration helpers            |
| `notify/`      | Garv    | Urgent alerts + periodic digest push (Telegram, email)   |
| `agents/`      | Garv    | AI triage agents and digest generation                   |
| `docs/`        | shared  | `SCHEMA.md` — DB contract between halves                 |

The two halves communicate only through `sessions.db`. See [docs/SCHEMA.md](docs/SCHEMA.md)
for table definitions, status lifecycle, and which side writes which fields.

## License

MIT — see [LICENSE](LICENSE).
