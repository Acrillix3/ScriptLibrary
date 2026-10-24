#!/bin/sh
# What it does
# Inventory loaded kernel modules, PCI drivers, network firmware versions, and recent firmware failure counts.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-drivers-and-firmware
DESCRIPTION='Inventory loaded kernel modules, PCI drivers, network firmware versions, and recent firmware failure counts.'
FLAGS='No script-specific flags.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

if [ -r "$ROOT_FS/proc/modules" ]; then
    driver_modules() { awk '{print $1, "bytes=" $2, "references=" $3, "state=" $5}' "$ROOT_FS/proc/modules"; }
    capture loaded_modules driver_modules
else finding Unknown loaded_modules "Kernel module inventory is not readable."; fi
if have lspci; then capture pci_drivers lspci -k
else finding Unknown pci_drivers "lspci is unavailable."; fi
driver_interfaces=0
for driver_path in "$ROOT_FS"/sys/class/net/*; do
    [ -d "$driver_path" ] || continue
    driver_name=$(basename "$driver_path")
    [ "$driver_name" = lo ] && continue
    driver_interfaces=$((driver_interfaces + 1))
    if [ -L "$driver_path/device/driver" ] && have readlink; then
        driver_link=$(readlink "$driver_path/device/driver" 2>/dev/null)
        fact "$driver_name.driver" "$(basename "$driver_link")"
    else
        finding Unknown "$driver_name.driver" "No bound device driver was exposed by sysfs."
    fi
    if have ethtool; then
        driver_ethtool() {
            driver_ethtool_data=$(ethtool -i "$1" 2>/dev/null)
            driver_ethtool_rc=$?
            [ "$driver_ethtool_rc" -eq 0 ] || return "$driver_ethtool_rc"
            printf '%s\n' "$driver_ethtool_data" | awk -F: '/^(driver|version|firmware-version|bus-info):/ {print}'
        }
        capture "firmware_$driver_name" driver_ethtool "$driver_name"
    fi
done
driver_log_summary() {
    driver_logs=$(journalctl -k -b --no-pager -n 1000 -o cat 2>/dev/null)
    driver_rc=$?
    [ "$driver_rc" -eq 0 ] || return "$driver_rc"
    printf '%s\n' "$driver_logs" | awk '
        {s=tolower($0)}
        s ~ /firmware/ && s ~ /fail|error|not found|missing/ {firmware++}
        s ~ /module/ && s ~ /verification failed|signature|unknown symbol/ {modules++}
        END {printf "firmware_failure_candidates=%d\nmodule_loading_candidates=%d\n", firmware, modules}
    '
}
if have journalctl; then
    capture kernel_driver_counts driver_log_summary
    finding Info log_scope "Counts cover at most the last 1000 kernel entries in this boot. Raw messages and command lines are excluded."
else finding Unknown firmware_failures "journalctl is unavailable; no complete firmware failure assessment is possible."; fi
finding Info firmware_scope "Firmware availability is not an update comparison; no firmware download, module unload, or installation occurs."

finish
