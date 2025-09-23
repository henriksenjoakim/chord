#!/usr/bin/env sh
set -eu

M=$1
TTL=$2
CONTPORT=$3
CWD=$PWD

echo "Checking environment"

if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
  echo "Environment is set up, skipping setup"
else
  echo "Could not find environment, setting up..."
  python3 -m venv venv
fi
source venv/bin/activate

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

if pip list | grep requests; then
  echo "Requests is installed, skipping.."
else
  echo "Requestst not found, installing.."
  pip install requests
fi

deactivate
echo "Swarming, please wait..."

CURRENTHOST=$(hostname -s)
RINGSIZE=$(awk -v x="$M" 'BEGIN { print 2^x }')
HOSTS=$(bash /share/ifi/available-nodes.sh | awk 'NF' | shuf -n "$RINGSIZE")
echo "Setting up with m = $2 Ringsize = $RINGSIZE ContactNode =$CURRENTHOST"
JSON_STR=""
FIRSTNODE=""
CONTACTNODE=""
first=1
for host in $HOSTS; do
  port=$(shuf -i 30000-65000 -n 1)
  echo "Setting up on $host:$port"
  if [ $first -eq 1 ]; then
    #FIRSTNODE=$host
    FIRSTNODE=$CURRENTHOST
    ssh -f "$host" "cd $CWD; source venv/bin/activate; python server.py $CONTPORT $M $TTL create > $CWD/tmp.log 2>&1 &"
    JSON_STR="${FIRSTNODE}:${CONTPORT}"
    CONTACTNODE="${FIRSTNODE}:${CONTPORT}"
    echo "Setting up on $FIRSTNODE:$CONTPORT"
    first=0
  fi
  if [ $first -eq 0 ]; then
    ssh -f "$host" "cd $CWD; source venv/bin/activate; python server.py $port $M $TTL join $FIRSTNODE > $CWD/tmp.log 2>&1 &"
    JSON_STR="$JSON_STR ${host}:${port}"
  fi
  sleep 1
done
echo "Waiting for startups..."
sleep 3
echo "Servers are running on:"
echo "$JSON_STR"
echo "Servers will automatically stop in $TTL seconds"
echo "Running testscript on $CONTACTNODE"
python3 chord-tester.py "$CONTACTNODE"
#./clean.sh
echo "Run script done"
