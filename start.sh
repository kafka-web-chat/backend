#!/usr/bin/env sh


python3 rest-server.py > /dev/null 2>&1  &
restServer=$!

python3 websocket-server.py > /dev/null 2>&1  &
wsServer=$!


echo "Servers running"
echo "PIDs: $restServer, $wsServer"
read -n1 -r -p "Press any key to close..." key

kill -9 $restServer
kill -9 $wsServer
