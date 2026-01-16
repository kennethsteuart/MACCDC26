#!/bin/bash

echo "[+] Hunting malicious processes..."

SUSPICIOUS_PROCS=$(ps aux | awk '
/bash -i|nc |ncat|socat|perl -e|python -c|\/dev\/tcp|\/tmp\/|\/dev\/shm/ {
  print $2
}')

for pid in $SUSPICIOUS_PROCS; do
  echo "[!] Killing PID $pid"
  kill -9 $pid 2>/dev/null
done

echo "[+] Checking for shells spawned by cron or init..."

ps -eo pid,ppid,cmd | awk '
($2 == 1 || $2 ~ /cron/) && $3 ~ /bash|sh/ { print $1 }
' | while read pid; do
  echo "[!] Killing suspicious shell PID $pid"
  kill -9 $pid 2>/dev/null
done

echo "[+] Done."
