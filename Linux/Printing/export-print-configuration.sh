#!/bin/sh
# What it does
# Export sanitized CUPS queue and security metadata into the private report directory.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags; this is a metadata export, not a complete restorable CUPS backup.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=export-print-configuration
DESCRIPTION='Export sanitized CUPS queue and security metadata into the private report directory.'
FLAGS='No script-specific flags; this is a metadata export, not a complete restorable CUPS backup.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


if have lpstat; then
    capture default-printer lpstat -d
    capture queue-state lpstat -p
    capture queue-accepting lpstat -a
    export_devices() {
        devices=$(lpstat -v 2>/dev/null) || return $?
        printf '%s\n' "$devices" | sed -E 's#(://)[^ ]*@#\1[redacted]@#g; s#[?][^ ]*#?[omitted]#g'
    }
    capture sanitized-devices export_devices
else finding Unknown cups "CUPS client tools are unavailable."; fi
if [ -r /etc/cups/printers.conf ]; then
    printer_metadata() { awk '/^<Printer / || /^<DefaultPrinter / || /^(Shared|State|Accepting|ErrorPolicy|OpPolicy) / {print}' /etc/cups/printers.conf; }
    capture queue-metadata printer_metadata
else finding Unknown printer-metadata "printers.conf is unavailable or unreadable."; fi
if [ -r /etc/cups/cupsd.conf ]; then
    cups_security() { awk '$1~/^(Listen|Port|Browsing|BrowseLocalProtocols|WebInterface|DefaultAuthType|DefaultEncryption)$/ {print}' /etc/cups/cupsd.conf; }
    capture scheduler-metadata cups_security
else finding Unknown scheduler-metadata "cupsd.conf is unavailable or unreadable."; fi
if [ -d /etc/cups/ppd ]; then
    ppd_inventory() { find /etc/cups/ppd -maxdepth 1 -type f -name '*.ppd' -print 2>/dev/null; }
    capture ppd-file-names ppd_inventory
fi
finding Info export "Metadata is stored in this run's private report. Raw configuration, certificates, private keys, credentials, and spool documents are excluded."
finding Info restore "Use this report to review queue definitions; it cannot restore a complete CUPS server."

finish
