#!/bin/sh
# What it does
# Inspect active resolver settings and optional forward and reverse lookups.
# Available flags
# --help; --output-dir DIRECTORY; --name HOSTNAME --address IP --server DNS_IP; lookups use the current resolver unless --server is supplied.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-dns-configuration
DESCRIPTION='Inspect active resolver settings and optional forward and reverse lookups.'
FLAGS='--name HOSTNAME --address IP --server DNS_IP; lookups use the current resolver unless --server is supplied.'
OPTIONS='name address server'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


name=$(arg name '')
address=$(arg address '')
server=$(arg server '')
for value in "$name" "$address" "$server"; do
    case "$value" in -*|*'/'*|*'@'*|*' '*|*'
'*) die "DNS inputs must be single hostnames or IP addresses."; esac
done
if [ -r /etc/resolv.conf ]; then
    resolver_projection() { awk '$1=="nameserver" || $1=="search" || $1=="domain" || $1=="options" {print}' /etc/resolv.conf; }
    capture resolv-conf resolver_projection
else
    finding Unknown resolv-conf "/etc/resolv.conf is unavailable or unreadable."
fi
if have resolvectl; then
    capture split-dns resolvectl status
elif have nmcli; then
    capture networkmanager-dns nmcli -f GENERAL.DEVICE,IP4.DNS,IP4.DOMAIN,IP6.DNS,IP6.DOMAIN device show
else
    finding Unknown split-dns "No supported split-DNS status provider; resolv.conf alone may be incomplete."
fi
if [ -n "$name" ]; then
    if have dig; then
        if [ -n "$server" ]; then capture forward dig "@$server" "$name" +time=3 +tries=1 +noall +answer +comments; else capture forward dig "$name" +time=3 +tries=1 +noall +answer +comments; fi
    elif have getent && [ -z "$server" ]; then capture forward getent ahosts "$name"
    else finding Unknown forward "dig is needed for an explicit DNS server; getent can test only the configured resolver."; fi
fi
if [ -n "$address" ]; then
    if have dig; then
        if [ -n "$server" ]; then capture reverse dig "@$server" -x "$address" +time=3 +tries=1 +noall +answer +comments; else capture reverse dig -x "$address" +time=3 +tries=1 +noall +answer +comments; fi
    else finding Unknown reverse "dig is required for an explicit reverse-DNS query."; fi
fi
finding Info interpretation "A successful query command can still return NXDOMAIN or SERVFAIL; inspect the recorded DNS status."

finish
