#!/bin/sh
# What it does
# Inspect SSH service configuration and listeners, with an optional TCP reachability test.
# Available flags
# --help; --output-dir DIRECTORY; --target HOST --port NUMBER (default 22); --user USER --client-address IP --local-address IP provide an sshd Match context.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=test-remote-access
DESCRIPTION='Inspect SSH service configuration and listeners, with an optional TCP reachability test.'
FLAGS='--target HOST --port NUMBER (default 22); --user USER --client-address IP --local-address IP provide an sshd Match context.'
OPTIONS='target port user client-address local-address'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


target=$(arg target '')
port=$(arg port 22)
user=$(arg user root)
client=$(arg client-address 127.0.0.1)
local_address=$(arg local-address 127.0.0.1)
case "$port" in ''|*[!0-9]*) die "Port must be numeric.";; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "Port must be 1-65535."
for value in "$target" "$user" "$client" "$local_address"; do case "$value" in -*|*','*|*'='*|*' '*|*'
'*) die "Invalid SSH test context."; esac; done
if have sshd; then
    if sshd -t >/dev/null 2>&1; then finding Pass sshd-syntax "SSHD configuration syntax passed."; else finding Unknown sshd-syntax "Syntax check failed or host keys/configuration are unreadable; rerun with appropriate access."; fi
    sshd_projection() { effective=$(sshd -T -C "user=$user,host=localhost,addr=$client,laddr=$local_address,lport=$port" 2>/dev/null) || return $?; printf '%s\n' "$effective" | awk '$1~/^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods|allowtcpforwarding|maxauthtries|usepam)$/ {print}'; }
    capture sshd-effective sshd_projection
    finding Info sshd-context "Effective rules are for the selected user and address context only."
else finding Unknown sshd "SSHD binary is unavailable."; fi
if have ss; then capture listening-sockets ss -lnt; else finding Unknown listeners "ss is unavailable."; fi
if have ip; then capture routes ip route show; fi
if [ -n "$target" ]; then
    case "$target" in *'/'*|*'@'*) die "Use a hostname or address without credentials."; esac
    if have python3; then
        capture ssh-tcp python3 -c 'import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),3); s.close(); print("TCP connection established; authentication not attempted")' "$target" "$port"
        if [ "$LAST_CAPTURE_RC" = 0 ]; then finding Pass ssh-tcp "TCP endpoint reachable; SSH authentication was not attempted."; else finding Fail ssh-tcp "TCP endpoint unavailable."; fi
    else finding Unknown ssh-tcp "Python 3 is needed for the optional bounded TCP test."; fi
fi
finding Info firewall "Use audit-firewall-rules.sh to correlate local policy; this script never alters access."

finish
