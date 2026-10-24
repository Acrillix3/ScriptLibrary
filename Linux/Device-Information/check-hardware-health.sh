#!/bin/sh
# What it does
# Read existing SMART/NVMe health and thermal sensors without starting tests or waking standby disks.
# Available flags
# --help; --output-dir DIRECTORY; --device /dev/DEVICE (optional); --temperature-warn CELSIUS (default 80).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=check-hardware-health
DESCRIPTION='Read existing SMART/NVMe health and thermal sensors without starting tests or waking standby disks.'
FLAGS='--device /dev/DEVICE (optional); --temperature-warn CELSIUS (default 80).'
OPTIONS='device temperature-warn'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

health_device=$(arg device "")
health_temp=$(arg temperature-warn 80)
case "$health_temp" in ''|*[!0-9]*) die "temperature-warn must be an integer from 1 through 150.";; esac
[ "$health_temp" -ge 1 ] && [ "$health_temp" -le 150 ] || die "temperature-warn must be from 1 through 150."
health_smart() {
    health_output=$(smartctl -n standby -H -A "$1" 2>/dev/null)
    health_rc=$?
    printf 'device=%s\nsmartctl_exit_status=%s\n' "$1" "$health_rc"
    printf '%s\n' "$health_output" | awk '
        /SMART overall-health|SMART Health Status|Critical Warning|Temperature:|Available Spare:|Percentage Used:|Media and Data Integrity Errors:|Error Information Log Entries:|Power_On_Hours|Reallocated_Sector_Ct|Current_Pending_Sector|Offline_Uncorrectable|Temperature_Celsius|Airflow_Temperature_Cel|standby|STANDBY|Unsupported|unsupported|Read Device Identity failed/ {print}
    '
    if [ $((health_rc & 7)) -ne 0 ]; then
        finding Unknown "smart.$1" "SMART data is unavailable, unsupported, access restricted, or the disk is in standby; see exit status."
    elif [ $((health_rc & 8)) -ne 0 ]; then
        finding Fail "smart.$1" "The device reports a failing SMART health status."
    elif [ $((health_rc & 240)) -ne 0 ]; then
        finding Warn "smart.$1" "SMART reports attributes or historical error/self-test entries requiring review."
    elif printf '%s\n' "$health_output" | grep -Eq 'PASSED|Health Status: OK'; then
        finding Pass "smart.$1" "The device reports a passing overall status; review individual attributes too."
    else
        finding Unknown "smart.$1" "The command succeeded but a recognized overall health result was not present."
    fi
}
health_nvme() {
    health_nvme_output=$(nvme smart-log "$1" 2>/dev/null)
    health_nvme_rc=$?
    if [ "$health_nvme_rc" -ne 0 ]; then
        finding Unknown "nvme.$1" "NVMe health data could not be read."
        return "$health_nvme_rc"
    fi
    printf '%s\n' "$health_nvme_output" | awk -F: '/critical_warning|temperature|available_spare|percentage_used|media_errors|num_err_log_entries|power_on_hours/ {print}'
    finding Info "nvme.$1" "Health counters were collected; no device self-test was started."
}
health_count=0
if [ -n "$health_device" ]; then
    case "$health_device" in /dev/*) ;; *) die "device must be an absolute path below /dev.";; esac
    [ -b "$health_device" ] || die "device must identify an existing block device."
    if have smartctl; then capture smart_selected health_smart "$health_device"
    elif have nvme; then
        case "$health_device" in /dev/nvme*) capture nvme_selected health_nvme "$health_device";; *) finding Unknown smart "smartctl is unavailable for the selected device.";; esac
    else finding Unknown disk_health "Install an approved smartmontools or NVMe diagnostic package separately."; fi
else
    for health_sys in "$ROOT_FS"/sys/block/*; do
        [ -d "$health_sys" ] || continue
        health_name=$(basename "$health_sys")
        case "$health_name" in sd*|hd*|nvme*|vd*|xvd*) ;; *) continue;; esac
        health_count=$((health_count + 1))
        [ "$health_count" -le 16 ] || { finding Warn disk_scope "Only the first 16 eligible devices were queried; select another with --device."; break; }
        if have smartctl; then capture "smart_$health_name" health_smart "/dev/$health_name"
        elif have nvme; then
            case "$health_name" in nvme*) capture "nvme_$health_name" health_nvme "/dev/$health_name";; *) finding Unknown "disk.$health_name" "smartctl is unavailable."; esac
        else finding Unknown "disk.$health_name" "No supported disk-health command is installed."; fi
    done
    [ "$health_count" -gt 0 ] || finding Unknown disk_health "No eligible sysfs block devices were visible."
fi
health_zones=0
for health_zone in "$ROOT_FS"/sys/class/thermal/thermal_zone*; do
    [ -r "$health_zone/temp" ] || continue
    health_raw=$(cat "$health_zone/temp" 2>/dev/null)
    case "$health_raw" in ''|*[!0-9]*) continue;; esac
    health_zones=$((health_zones + 1))
    health_zone_name=$(basename "$health_zone")
    fact "$health_zone_name.millicelsius" "$health_raw"
    [ ! -r "$health_zone/type" ] || fact "$health_zone_name.type" "$(head -c 128 "$health_zone/type" 2>/dev/null)"
    if [ "$health_raw" -ge $((health_temp * 1000)) ]; then
        finding Warn "$health_zone_name" "Temperature meets the selected warning threshold of $health_temp Celsius."
    fi
done
[ "$health_zones" -gt 0 ] || finding Unknown temperature "No readable thermal-zone sensors were exposed."
finding Info health_scope "RAID controllers and some USB bridges need device-specific tooling. This is a health read, not a surface or memory test."

finish
