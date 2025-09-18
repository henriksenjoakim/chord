#!/usr/bin/env sh
set -eu

NUM=${1:-3}
CWD=$PWD

echo "Checking environment"
sleep 1

if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
  echo "Environment is set up, skipping setup"
else
  echo "Could not find environment, setting up..."
  python3 -m venv venv
fi
source venv/bin/activate
sleep 5
if pip list | grep Flask; then
  echo "Flask is installed, skipping.."
else
  echo "Flask not found, installing.."
  pip install flask
fi

if pip list | grep sockets; then
  echo "Socket is installed, skipping.."
else
  echo "Socket not found, installing.."
  pip install sockets
fi
deactivate
sleep 2
echo "Swarming, please wait..."
sleep 2

HOSTS=$(bash /share/ifi/available-nodes.sh | awk 'NF' | shuf -n "$NUM")

JSON_STR="["

first=1
for host in $HOSTS; do
  port=$(shuf -i 30000-65000 -n 1)
  echo "Setting up on $host:$port"
  #json="[\"$host:$port\"]"
  #echo "starting server"
  if [ $first -eq 0 ]; then
    JSON_STR="$JSON_STR, "
  fi
  JSON_STR="$JSON_STR\"${host}:${port}\""
  first=0
  #ENTRIES+=("\"${host}:${port}\"")
  ssh -f "$host" "cd $CWD; source venv/bin/activate; python server.py $port > $CWD/tmp.log 2>&1 &"
done
echo "Waiting for startups..."
sleep 3
JSON_STR="$JSON_STR]"
echo "Servers are running on:"
echo "$JSON_STR "
echo "Servers will automatically stop in 30 seconds for safety"
echo "Running testscript on $JSON_STR"
sleep 1
python3 testscript.py "$JSON_STR"
#./clean.sh
echo "Run script done"
