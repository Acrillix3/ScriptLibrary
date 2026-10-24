#!/bin/sh
# What it does
# Inspect interfaces, routes, and an explicitly selected TCP endpoint.
# Available flags
# --help; --output-dir DIRECTORY; --target HOST --port NUMBER (default 443); no external target is contacted unless selected.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=test-network-connectivity
DESCRIPTION='Inspect interfaces, routes, and an explicitly selected TCP endpoint.'
FLAGS='--target HOST --port NUMBER (default 443); no external target is contacted unless selected.'
OPTIONS='target port'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


target=$(arg target '')
port=$(arg port 443)
case "$port" in ''|*[!0-9]*) die "Port must be 1-65535.";; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "Port must be 1-65535."
case "$target" in -*|*'/'*|*'@'*|*' '*|*'
'*) die "Target must be a hostname or IP address without credentials.";; esac
if have ip; then
    capture interfaces ip -brief address
    capture routes ip route show
    capture routes6 ip -6 route show
elif have ifconfig; then
    capture interfaces ifconfig -a
    if have route; then capture routes route -n; else finding Unknown routes "No supported route inventory tool."; fi
else
    finding Unknown interfaces "Install iproute2 using an approved package process."
fi
if [ -n "$target" ]; then
    if have getent; then capture name-resolution getent ahosts "$target"; fi
    if have python3; then
        capture tcp-endpoint python3 -c 'import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),3); s.close(); print("TCP connection established")' "$target" "$port"
        if [ "$LAST_CAPTURE_RC" = 0 ]; then finding Pass tcp-endpoint "TCP connection established to $target:$port."; else finding Fail tcp-endpoint "TCP connection failed; check routing, listener, and firewall."; fi
    elif have nc && nc -h 2>&1 | grep -q -- '-z'; then
        capture tcp-endpoint nc -z -w 3 "$target" "$port"
        if [ "$LAST_CAPTURE_RC" = 0 ]; then finding Pass tcp-endpoint "TCP connection established."; else finding Fail tcp-endpoint "TCP connection failed."; fi
    else
        finding Unknown tcp-endpoint "Python 3 or netcat with -z is needed; no packages were installed."
    fi
else
    finding Info tcp-endpoint "Select --target and --port to test a TCP endpoint."
fi

finish
