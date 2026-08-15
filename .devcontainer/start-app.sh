#!/usr/bin/env bash
# Startuje aplikację w tle na 127.0.0.1:8001 przy każdym starcie kontenera
# (wołane z "postStartCommand" w devcontainer.json). Port nie jest
# forwardowany na hosta - ruch wchodzi przez nginx (80/443/8000), który
# proxuje na 8001 w tym samym namespace sieciowym.
#
# Skrypt można też odpalić ręcznie: .devcontainer/start-app.sh
set -euo pipefail

APP_DIR="/workspaces/PyMitiveCA/PyMitiveCA"
PORT=8001
LOG=/tmp/runserver.log
PIDFILE=/tmp/runserver.pid

# Idempotencja: przy restarcie kontenera (albo ręcznym wywołaniu) nie
# odpalamy drugiego runservera, bo dostałby "Address already in use".
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Aplikacja już działa (PID $(cat "$PIDFILE")), pomijam start."
    exit 0
fi

# Postgres jest w tym samym namespace sieciowym (network_mode: service:db),
# więc czekamy na localhost:5432 - bez tego migrate przy starcie kontenera
# potrafi wystartować szybciej niż baza i wywalić się na connection refused.
echo "Czekam na PostgreSQL na localhost:5432..."
for _ in $(seq 1 30); do
    if python -c "import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(('127.0.0.1',5432))==0 else 1)"; then
        break
    fi
    sleep 1
done

cd "$APP_DIR"
python manage.py migrate --noinput

# nohup + & , bo runserver nigdy sam się nie kończy, a komenda na pierwszym
# planie blokowałaby start kontenera.
echo "Startuję runserver na 0.0.0.0:$PORT (log: $LOG)"
nohup python manage.py runserver "0.0.0.0:$PORT" > "$LOG" 2>&1 &
echo $! > "$PIDFILE"
