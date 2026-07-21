#!/bin/bash
set -e

# End-to-end smoke test of the UDP NAT-traversal rendezvous against the REAL
# enode binary. Builds enode + both simulators, starts the server with the
# local test config (memory engine, NAT enabled on :2004, dynIp pinned to
# 127.0.0.1 so there is no network probing and no database needed), then runs:
#
#   natsim1 (target)    - registers with OP_NAT_REGISTER_EX (version 1) and
#                         keepalives; exercises feature 1 (SYNC_EX) + feature 2
#                         (OP_NAT_PING keepalive ACK).
#   natsim2 (initiator) - registers, pairs via OP_NAT_SYNC2, hole-punches.
#
# PASS when natsim2 receives a PONG (exit 0). No Docker/DB required.

if [ ! -d "$PWD/scripts" ]; then
  echo "Please run this shell script from the project's root folder."
  exit 0
fi

CONFIG="enode.local.yaml"
NAT_ADDR="127.0.0.1:2004"
HASH1="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" # target
HASH2="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" # initiator

WORK="$(mktemp -d)"
ENODE_LOG="$WORK/enode.log"
SIM1_LOG="$WORK/natsim1.log"
ENODE_PID=""
SIM1_PID=""

cleanup() {
  [ -n "$SIM1_PID" ] && kill "$SIM1_PID" 2>/dev/null || true
  [ -n "$ENODE_PID" ] && kill "$ENODE_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

# wait_for FILE PATTERN TIMEOUT_SECS LABEL
wait_for() {
  local file="$1" pat="$2" timeout="$3" label="$4" waited=0
  while ! grep -q "$pat" "$file" 2>/dev/null; do
    sleep 0.2
    waited=$((waited + 1))
    if [ "$waited" -ge $((timeout * 5)) ]; then
      echo "FAIL: timed out waiting for $label"
      echo "----- $file -----"
      cat "$file" 2>/dev/null || true
      return 1
    fi
  done
}

echo "building enode, natsim1, natsim2 into $WORK ..."
go build -o "$WORK/enode" ./cmd/enode
go build -o "$WORK/natsim1" ./cmd/natsim1
go build -o "$WORK/natsim2" ./cmd/natsim2

echo "starting enode ($CONFIG) ..."
"$WORK/enode" -config "$CONFIG" >"$ENODE_LOG" 2>&1 &
ENODE_PID=$!
wait_for "$ENODE_LOG" "listening: nat-udp" 15 "enode nat-udp listener"

# Target stays up (no -exit-after-pong) and keepalives twice a second so the
# server's OP_NAT_PING keepalive ACK (feature 2) is observable; it is killed by
# the cleanup trap on exit.
echo "starting natsim1 (target, register-mode ex) ..."
"$WORK/natsim1" \
  -nat "$NAT_ADDR" -hash "$HASH1" \
  -register-mode ex -version 1 \
  -register-interval 0 -keepalive-interval 500ms \
  -timeout 25s >"$SIM1_LOG" 2>&1 &
SIM1_PID=$!
wait_for "$SIM1_LOG" "got OP_NAT_REGISTER ack" 15 "natsim1 registration"

echo "running natsim2 (initiator) ..."
if "$WORK/natsim2" -nat "$NAT_ADDR" -hash "$HASH2" -peer "$HASH1" -timeout 25s; then
  echo
  echo "PASS: natsim2 completed the NAT hole-punch (received PONG)"
  # Let a couple of keepalives round-trip, then surface feature-1/2 evidence.
  sleep 1.2
  grep -q "OP_NAT_SYNC_EX" "$SIM1_LOG" && echo "  - target received OP_NAT_SYNC_EX (feature 1)"
  grep -q "OP_NAT_PING" "$SIM1_LOG" && echo "  - target received OP_NAT_PING keepalive ACK (feature 2)"
  exit 0
else
  echo
  echo "FAIL: natsim2 did not complete the hole-punch"
  echo "----- natsim1 log -----"; cat "$SIM1_LOG" 2>/dev/null || true
  echo "----- enode log (tail) -----"; tail -20 "$ENODE_LOG" 2>/dev/null || true
  exit 1
fi
