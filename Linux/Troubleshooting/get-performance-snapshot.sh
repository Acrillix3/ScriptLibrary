#!/bin/sh
# What it does
# Collect bounded CPU, memory, disk counters, load, process names, and pressure-stall snapshots.
# Available flags
# --help; --output-dir DIRECTORY; --samples COUNT (default 5, maximum 10); --interval-seconds SECONDS (default 1, maximum 5).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=get-performance-snapshot
DESCRIPTION='Collect bounded CPU, memory, disk counters, load, process names, and pressure-stall snapshots.'
FLAGS='--samples COUNT (default 5, maximum 10); --interval-seconds SECONDS (default 1, maximum 5).'
OPTIONS='samples interval-seconds'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

perf_samples=$(arg samples 5)
perf_interval=$(arg interval-seconds 1)
for perf_number in "$perf_samples" "$perf_interval"; do
    case "$perf_number" in ''|*[!0-9]*) die "samples and interval-seconds must be positive integers.";; esac
    [ "$perf_number" -gt 0 ] || die "samples and interval-seconds must be greater than zero."
done
[ "$perf_samples" -le 10 ] && [ "$perf_interval" -le 5 ] || die "Maximums are 10 samples and a 5-second interval."
perf_snapshot() {
    perf_index=1
    while [ "$perf_index" -le "$perf_samples" ]; do
        printf 'sample=%s\n' "$perf_index"
        date -u '+utc=%Y-%m-%dT%H:%M:%SZ'
        if [ -r "$ROOT_FS/proc/stat" ]; then
            awk '$1=="cpu" {print "cpu_jiffies", $0}' "$ROOT_FS/proc/stat"
        fi
        if [ -r "$ROOT_FS/proc/loadavg" ]; then
            awk '{print "load_1m=" $1, "load_5m=" $2, "load_15m=" $3}' "$ROOT_FS/proc/loadavg"
        fi
        if [ -r "$ROOT_FS/proc/meminfo" ]; then
            awk '/^(MemTotal|MemAvailable|MemFree|Buffers|Cached|SwapTotal|SwapFree|Dirty|Writeback):/ {print}' "$ROOT_FS/proc/meminfo"
        fi
        for perf_resource in cpu memory io; do
            if [ -r "$ROOT_FS/proc/pressure/$perf_resource" ]; then
                awk -v r="$perf_resource" '{print "pressure_" r, $0}' "$ROOT_FS/proc/pressure/$perf_resource"
            fi
        done
        perf_index=$((perf_index + 1))
        [ "$perf_index" -gt "$perf_samples" ] || sleep "$perf_interval"
    done
}
if [ -r "$ROOT_FS/proc/stat" ] && [ -r "$ROOT_FS/proc/meminfo" ]; then
    capture performance_samples perf_snapshot
else finding Unknown performance_samples "Required procfs CPU or memory counters are unavailable."; fi
perf_processes() {
    perf_ps=$(ps -eo pid,ppid,comm,pcpu,pmem --sort=-pcpu 2>/dev/null)
    perf_ps_rc=$?
    if [ "$perf_ps_rc" -eq 0 ]; then
        printf '%s\n' "$perf_ps" | awk 'NR<=31 {print}'
    else
        perf_ps=$(ps -o pid,ppid,comm 2>/dev/null)
        perf_ps_rc=$?
        [ "$perf_ps_rc" -eq 0 ] || return "$perf_ps_rc"
        printf '%s\n' "$perf_ps" | awk 'NR<=31 {print}'
        finding Unknown process_cpu "This ps implementation lacks the selected CPU/memory sorting fields; process-name metadata is limited."
    fi
}
if have ps; then capture process_metadata perf_processes
else finding Unknown process_metadata "ps is unavailable."; fi
if [ -r "$ROOT_FS/proc/diskstats" ]; then
    perf_disks() {
        awk 'NF>=14 {
            print "device=" $3, "reads_completed=" $4, "sectors_read=" $6, "read_ms=" $7, "writes_completed=" $8, "sectors_written=" $10, "write_ms=" $11, "in_flight=" $12, "io_ms=" $13, "weighted_io_ms=" $14
        }' "$ROOT_FS/proc/diskstats"
    }
    capture disk_counters perf_disks
else finding Unknown disk_counters "Disk counters are unavailable."; fi
for perf_resource in cpu memory io; do
    [ -r "$ROOT_FS/proc/pressure/$perf_resource" ] || finding Unknown "pressure.$perf_resource" "The kernel does not expose this PSI counter."
done
finding Info performance_scope "CPU and disk values are cumulative kernel counters, not benchmark results; compare successive samples. ps CPU values can be lifetime averages. Process arguments and environment variables are excluded."

finish
