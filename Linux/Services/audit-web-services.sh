#!/bin/sh
# What it does
# Check installed nginx and Apache configuration syntax, listeners, and optional remote TLS certificate dates.
# Available flags
# --help; --output-dir DIRECTORY; --host HOST --port NUMBER (default 443) selects a TLS endpoint; no external endpoint is contacted otherwise.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-web-services
DESCRIPTION='Check installed nginx and Apache configuration syntax, listeners, and optional remote TLS certificate dates.'
FLAGS='--host HOST --port NUMBER (default 443) selects a TLS endpoint; no external endpoint is contacted otherwise.'
OPTIONS='host port'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


host=$(arg host '')
port=$(arg port 443)
case "$host" in -*|*[!A-Za-z0-9.:-]*) die "TLS host must be a hostname or IP address."; esac
case "$port" in ''|*[!0-9]*) die "Port must be numeric."; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "Port must be 1-65535."
web_found=0
if have nginx; then
    web_found=1
    if nginx -t >/dev/null 2>&1; then finding Pass nginx-syntax "nginx syntax check passed."; else finding Unknown nginx-syntax "Syntax test failed or required files are unreadable; raw errors are withheld because configuration may contain credentials."; fi
    nginx_version() { nginx -v 2>&1; }
    capture nginx-version nginx_version
fi
apache_binary=''
for candidate in apache2ctl apachectl httpd; do if have "$candidate"; then apache_binary=$candidate; break; fi; done
if [ -n "$apache_binary" ]; then
    web_found=1
    if "$apache_binary" -t >/dev/null 2>&1; then finding Pass apache-syntax "Apache syntax check passed."; else finding Unknown apache-syntax "Syntax test failed or required files are unreadable; inspect locally with suitable access."; fi
    capture apache-version "$apache_binary" -v
fi
[ "$web_found" = 1 ] || finding Unknown web-server "Neither nginx nor Apache administrative binaries were found."
if have ss; then capture tcp-listeners ss -lnt; else finding Unknown listeners "ss is unavailable."; fi
if [ "$INIT_SYSTEM" = systemd ]; then
    capture web-service-state systemctl show nginx.service apache2.service httpd.service --property=Id,LoadState,ActiveState,SubState,Result,NRestarts
fi
if [ -n "$host" ]; then
    if have openssl && have timeout; then
        case "$host" in *:*) endpoint="[$host]:$port";; *) endpoint="$host:$port";; esac
        tls_dates() { timeout 8 openssl s_client -connect "$endpoint" -servername "$host" </dev/null 2>/dev/null | openssl x509 -noout -dates -issuer -subject -fingerprint -sha256; }
        capture tls-certificate tls_dates
        if [ "$LAST_CAPTURE_RC" = 0 ]; then finding Info tls-certificate "Public certificate dates were retrieved. This inspection does not establish certificate-chain or hostname trust."; else finding Fail tls-certificate "A certificate could not be retrieved or decoded."; fi
    else finding Unknown tls-certificate "openssl and timeout are required for a bounded TLS query."; fi
fi
finding Info errors "Raw access/error logs, configuration bodies, private keys, and service command arguments are excluded. Correlate failures locally without exporting secrets."

finish
