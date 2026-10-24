#!/bin/sh
# What it does
# Inventory the local operating system, CPU, memory, hardware model, firmware, and virtualization.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=get-device-information
DESCRIPTION='Inventory the local operating system, CPU, memory, hardware model, firmware, and virtualization.'
FLAGS='No script-specific flags.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

fact operating_system "$OS_ID $OS_VERSION"
fact operating_system_family "$OS_FAMILY"
fact init_system "$INIT_SYSTEM"
capture kernel uname -srm
if have getconf; then capture logical_processors getconf _NPROCESSORS_ONLN; fi
if have lscpu; then
    device_cpu() {
        device_cpu_data=$(lscpu 2>/dev/null)
        device_cpu_rc=$?
        [ "$device_cpu_rc" -eq 0 ] || return "$device_cpu_rc"
        printf '%s\n' "$device_cpu_data" | awk -F: '/^(Architecture|CPU op-mode|Byte Order|CPU\(s\)|On-line CPU|Vendor ID|Model name|Thread|Core|Socket|Virtualization|Hypervisor vendor)/ {print}'
    }
    capture cpu_inventory device_cpu
elif [ -r "$ROOT_FS/proc/cpuinfo" ]; then
    device_cpu() {
        awk -F: '/^(processor|model name|Hardware|CPU architecture|vendor_id)[[:space:]]*:/ {print; n++; if(n >= 80) exit}' "$ROOT_FS/proc/cpuinfo"
    }
    capture cpu_inventory device_cpu
else
    finding Unknown cpu_inventory "Neither lscpu nor readable procfs CPU information is available."
fi
if [ -r "$ROOT_FS/proc/meminfo" ]; then
    device_memory() {
        awk '/^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree|HugePages_Total|Hugepagesize):/ {print}' "$ROOT_FS/proc/meminfo"
    }
    capture memory_inventory device_memory
else
    finding Unknown memory_inventory "Memory information is unavailable."
fi
for device_field in sys_vendor product_name product_version board_vendor board_name bios_vendor bios_version bios_date; do
    device_file="$ROOT_FS/sys/class/dmi/id/$device_field"
    if [ -r "$device_file" ]; then
        fact "hardware.$device_field" "$(head -c 512 "$device_file" 2>/dev/null)"
    fi
done
if have systemd-detect-virt; then
    device_virt=$(systemd-detect-virt 2>/dev/null)
    device_virt_rc=$?
    if [ "$device_virt_rc" -eq 0 ]; then
        fact virtualization "$device_virt"
    elif [ "$device_virt_rc" -eq 1 ] && [ "$device_virt" = none ]; then
        fact virtualization "No virtualization detected by systemd-detect-virt."
    else
        finding Unknown virtualization "Virtualization detection was inconclusive."
    fi
else
    finding Unknown virtualization "systemd-detect-virt is unavailable; hardware inventory does not prove bare metal."
fi
if [ -r "$ROOT_FS/proc/uptime" ]; then
    fact uptime_seconds "$(awk '{print $1}' "$ROOT_FS/proc/uptime")"
fi
finding Info inventory_scope "Serial numbers, machine IDs, and hardware UUIDs are excluded."

finish
