#!/usr/bin/env bash

set -euo pipefail

pid=7626

ps -up $pid
echo ""
go build
sudo -E ./patch -pid $pid -obj lib.so -new lib.Sum -old main.Sub
echo ""
ps -up $pid
