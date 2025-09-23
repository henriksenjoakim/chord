#!/usr/bin/env sh
set -eu

HOST=$(bash /share/ifi/available-nodes.sh | awk 'NF' | shuf -n 1)
echo "-Node roulette- Joining: $HOST"
ssh -f "$HOST "cd /mnt/users/jhe028/inf-3200-a2/chord/jhe028/src;"
