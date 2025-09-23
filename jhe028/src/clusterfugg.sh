#!/usr/bin/env sh
set -eu

HOST=$(bash /share/ifi/available-nodes.sh | awk 'NF' | shuf -n "1")
echo "-Node roulette- Joining: $HOST"
ssh "$HOST"
