#!/bin/sh
# What it does
# Test a selected printer TCP endpoint and optionally read-only IPP attributes.
# Available flags
# --help; --output-dir DIRECTORY; --target HOST --protocol ipp|ipps|raw (default ipp) --port NUMBER --uri ipp[s]://HOST/PATH; IPP defaults to /ipp/print and port 631, raw to 9100.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=test-printer-connectivity
DESCRIPTION='Test a selected printer TCP endpoint and optionally read-only IPP attributes.'
FLAGS='--target HOST --protocol ipp|ipps|raw (default ipp) --port NUMBER --uri ipp[s]://HOST/PATH; IPP defaults to /ipp/print and port 631, raw to 9100.'
OPTIONS='target protocol port uri'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


target=$(arg target '')
protocol=$(arg protocol ipp)
case "$protocol" in ipp|ipps) default_port=631;; raw) default_port=9100;; *) die "Protocol must be ipp, ipps, or raw.";; esac
port=$(arg port "$default_port")
case "$target" in ''|-*|*[!A-Za-z0-9.:-]*) die "Specify a hostname or IP address without credentials."; esac
case "$port" in ''|*[!0-9]*) die "Invalid TCP port.";; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "Port must be 1-65535."
if have python3; then
    capture printer-tcp python3 -c 'import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),3); s.close(); print("TCP connection established")' "$target" "$port"
    if [ "$LAST_CAPTURE_RC" = 0 ]; then finding Pass printer-tcp "Selected printer port is reachable."; else finding Fail printer-tcp "Selected printer port is unavailable."; fi
else finding Unknown printer-tcp "Python 3 is needed for the bounded TCP test."; fi
if [ "$protocol" != raw ]; then
    uri=$(arg uri '')
    if [ -z "$uri" ]; then
        case "$target" in *:*) uri="$protocol://[$target]:$port/ipp/print";; *) uri="$protocol://$target:$port/ipp/print";; esac
    fi
    case "$uri" in "$protocol"://*) ;; *) die "URI must match the selected IPP protocol."; esac
    case "$uri" in *'@'*|*'?'*|*'#'*|*' '*|*'
'*) die "URI credentials, query strings, fragments, and whitespace are not accepted."; esac
    authority=$(printf '%s' "$uri" | cut -d/ -f3)
    case "$target" in *:*) expected_host="[$target]";; *) expected_host=$target;; esac
    if [ "$authority" != "$expected_host:$port" ]; then
        [ "$port" = 631 ] && [ "$authority" = "$expected_host" ] || die "IPP URI must match --target and --port."
    fi
    if have ipptool; then
        test_file=''
        for candidate in /usr/share/cups/ipptool/get-printer-attributes.test /usr/local/share/cups/ipptool/get-printer-attributes.test; do
            if [ -r "$candidate" ]; then test_file=$candidate; break; fi
        done
        if [ -n "$test_file" ]; then
            capture ipp-attributes ipptool -T 5 -t "$uri" "$test_file"
            if [ "$LAST_CAPTURE_RC" = 0 ]; then finding Pass ipp-attributes "Read-only Get-Printer-Attributes test passed."; else finding Fail ipp-attributes "IPP test failed; inspect the recorded result."; fi
        else finding Unknown ipp-attributes "The standard Get-Printer-Attributes test file is unavailable."; fi
    else finding Unknown ipp-attributes "ipptool is unavailable; TCP alone does not establish IPP health."; fi
else
    finding Info raw "No print data or test pages were submitted; RAW checks are limited to TCP reachability."
fi

finish
