#!/bin/bash
PORT=8000
PIDS=$(lsof -t -i:$PORT)
if [ -n "$PIDS" ]; then
    echo "Killing PIDs using port $PORT: $PIDS"
    kill -9 $PIDS
fi
