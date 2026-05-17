FROM python:3.11-slim

WORKDIR /app

COPY agents/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY agents /app/
COPY db /app/db

ENV DB_PATH=/data/sessions.db

# Apply the schema (idempotent — init.sql is CREATE TABLE IF NOT EXISTS) before
# triage starts, so we don't race ingest on cold boot.
CMD ["sh", "-c", "python -c \"import sqlite3, os; con=sqlite3.connect(os.environ['DB_PATH']); con.executescript(open('/app/db/init.sql').read()); con.close()\" && exec python -u triage.py"]
