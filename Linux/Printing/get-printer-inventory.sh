#!/bin/sh
# What it does
# List CUPS queues, default destination, accepting state, device endpoints, and installed driver choices.
# Available flags
# --help; --output-dir DIRECTORY; --queue NAME optionally limits queue details; installed driver listing remains global.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=get-printer-inventory
DESCRIPTION='List CUPS queues, default destination, accepting state, device endpoints, and installed driver choices.'
FLAGS='--queue NAME optionally limits queue details; installed driver listing remains global.'
OPTIONS=queue
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


queue=$(arg queue '')
case "$queue" in -*|*[!A-Za-z0-9_.-]*) die "Queue name must contain letters, digits, dot, underscore, or hyphen."; esac
if have lpstat; then
    capture cups-scheduler lpstat -r
    capture default-printer lpstat -d
    if [ -n "$queue" ]; then
        capture queues lpstat -p "$queue"
        capture accepting lpstat -a "$queue"
    else
        capture queues lpstat -p
        capture accepting lpstat -a
    fi
    printer_devices() {
        if [ -n "$queue" ]; then devices=$(lpstat -v "$queue" 2>/dev/null) || return $?; else devices=$(lpstat -v 2>/dev/null) || return $?; fi
        printf '%s\n' "$devices" | sed -E 's#(://)[^ ]*@#\1[redacted]@#g; s#[?][^ ]*#?[omitted]#g'
    }
    capture device-endpoints printer_devices
else finding Unknown cups "CUPS client tools are unavailable."; fi
if have lpinfo; then capture installed-drivers lpinfo -m; else finding Unknown drivers "lpinfo is unavailable."; fi
if [ -r /etc/cups/printers.conf ]; then
    sharing_projection() { awk '/^<Printer / || /^<DefaultPrinter / || /^Shared / {print}' /etc/cups/printers.conf; }
    capture sharing sharing_projection
else finding Unknown sharing "CUPS sharing metadata is unavailable or unreadable."; fi
finding Info privacy "No job contents, document names, authentication data, or raw CUPS configuration is collected."

finish
