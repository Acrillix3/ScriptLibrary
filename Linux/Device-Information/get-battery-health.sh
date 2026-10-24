#!/bin/sh
# What it does
# Read battery charge, cycle count, and full-capacity versus design-capacity wear from sysfs.
# Available flags
# --help; --output-dir DIRECTORY; --wear-warning-percent PERCENT (remaining design capacity; default 80).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=get-battery-health
DESCRIPTION='Read battery charge, cycle count, and full-capacity versus design-capacity wear from sysfs.'
FLAGS='--wear-warning-percent PERCENT (remaining design capacity; default 80).'
OPTIONS=wear-warning-percent
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

battery_threshold=$(arg wear-warning-percent 80)
case "$battery_threshold" in ''|*[!0-9]*) die "wear-warning-percent must be an integer from 1 through 100.";; esac
[ "$battery_threshold" -ge 1 ] && [ "$battery_threshold" -le 100 ] || die "wear-warning-percent must be from 1 through 100."
battery_count=0
for battery_path in "$ROOT_FS"/sys/class/power_supply/*; do
    [ -r "$battery_path/type" ] || continue
    [ "$(cat "$battery_path/type" 2>/dev/null)" = Battery ] || continue
    battery_count=$((battery_count + 1))
    battery_name=$(basename "$battery_path")
    for battery_field in status present capacity cycle_count energy_now energy_full energy_full_design charge_now charge_full charge_full_design voltage_now current_now power_now; do
        [ -r "$battery_path/$battery_field" ] || continue
        battery_value=$(head -c 128 "$battery_path/$battery_field" 2>/dev/null)
        fact "$battery_name.$battery_field" "$battery_value"
    done
    battery_full=""
    battery_design=""
    if [ -r "$battery_path/energy_full" ] && [ -r "$battery_path/energy_full_design" ]; then
        battery_full=$(cat "$battery_path/energy_full" 2>/dev/null)
        battery_design=$(cat "$battery_path/energy_full_design" 2>/dev/null)
    elif [ -r "$battery_path/charge_full" ] && [ -r "$battery_path/charge_full_design" ]; then
        battery_full=$(cat "$battery_path/charge_full" 2>/dev/null)
        battery_design=$(cat "$battery_path/charge_full_design" 2>/dev/null)
    fi
    case "$battery_full:$battery_design" in *[!0-9:]*|:*|*:) finding Unknown "$battery_name.wear" "A comparable numeric full/design capacity pair is unavailable."; continue;; esac
    [ "$battery_design" -gt 0 ] || { finding Unknown "$battery_name.wear" "Design capacity is zero or unavailable."; continue; }
    battery_percent=$(awk -v f="$battery_full" -v d="$battery_design" 'BEGIN {printf "%.1f", 100*f/d}')
    fact "$battery_name.percent_of_design" "$battery_percent"
    if awk -v p="$battery_percent" -v t="$battery_threshold" 'BEGIN {exit !(p<t)}'; then
        finding Warn "$battery_name.wear" "Remaining full capacity is $battery_percent percent of design, below $battery_threshold percent."
    else
        finding Pass "$battery_name.wear" "Reported full capacity meets the selected remaining-capacity threshold."
    fi
done
[ "$battery_count" -gt 0 ] || finding Unknown battery_inventory "No battery was exposed by sysfs; this can be normal on servers or VMs."
finding Info battery_units "energy fields use micro-watt-hours; charge fields use micro-amp-hours. Unlike quantities are never compared."

finish
