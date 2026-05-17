FROM python:3.11-slim

WORKDIR /app

# Tailer is stdlib-only, no pip install needed.
COPY ingest /app/ingest
COPY db /app/db

# /cowrie-log: bind-mounted from honeypot/var/log/cowrie (read-only).
# /data:       bind-mounted from ./data (shared with the triage container).
CMD ["python", "-u", "-m", "ingest.tail", \
     "--cowrie-log", "/cowrie-log/cowrie.json", \
     "--db", "/data/sessions.db", \
     "--state", "/data/.tail.state"]
