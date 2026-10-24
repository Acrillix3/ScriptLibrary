#!/bin/sh
# What it does
# Audit available firewall backends and local listeners without changing rules.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-firewall-rules
DESCRIPTION='Audit available firewall backends and local listeners without changing rules.'
FLAGS='No script-specific flags.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


observed=0
if have firewall-cmd; then
    capture firewalld-state firewall-cmd --state
    if [ "$LAST_CAPTURE_RC" = 0 ]; then
        observed=1
        capture firewalld-zones firewall-cmd --get-active-zones
        capture firewalld-runtime firewall-cmd --list-all-zones
        capture firewalld-permanent firewall-cmd --permanent --list-all-zones
    fi
fi
if have ufw; then
    capture ufw-state ufw status verbose
    if [ "$LAST_CAPTURE_RC" = 0 ]; then observed=1; fi
fi
if have nft; then
    nft_projection() { rules=$(nft list ruleset 2>/dev/null) || return $?; printf '%s\n' "$rules" | sed -E 's/comment "[^"]*"/comment "[omitted]"/g'; }
    capture nftables nft_projection
    finding Info nftables "Comments are omitted; permissions and command failure must be reviewed."
    observed=1
elif have iptables-save; then
    iptables_projection() { rules=$(iptables-save 2>/dev/null) || return $?; printf '%s\n' "$rules" | sed -E 's/--comment "[^"]*"/--comment "[omitted]"/g'; }
    capture iptables iptables_projection
    observed=1
fi
if have ss; then capture listening-sockets ss -lntu; elif have netstat; then capture listening-sockets netstat -lntu; else finding Unknown listeners "No supported socket inventory tool."; fi
[ "$observed" = 1 ] || finding Unknown firewall "No supported firewall provider is available."
finding Info exposure "Listening sockets and local rules do not prove exposure through upstream firewalls or cloud security groups."

finish
