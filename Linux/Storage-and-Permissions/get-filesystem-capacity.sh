#!/bin/sh
# What it does
# Check space and inode capacity on a selected filesystem and inventory mount types and read-only states.
# Available flags
# --help; --output-dir DIRECTORY; --path /PATH (default /); --space-warning-percent PERCENT (default 85); --inode-warning-percent PERCENT (default 85).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=get-filesystem-capacity
DESCRIPTION='Check space and inode capacity on a selected filesystem and inventory mount types and read-only states.'
FLAGS='--path /PATH (default /); --space-warning-percent PERCENT (default 85); --inode-warning-percent PERCENT (default 85).'
OPTIONS='path space-warning-percent inode-warning-percent'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

capacity_path=$(arg path /)
capacity_space=$(arg space-warning-percent 85)
capacity_inode=$(arg inode-warning-percent 85)
case "$capacity_path" in /*) ;; *) die "path must be absolute.";; esac
[ -e "$capacity_path" ] || die "path does not exist."
for capacity_value in "$capacity_space" "$capacity_inode"; do
    case "$capacity_value" in ''|*[!0-9]*) die "Capacity thresholds must be integers from 1 through 100.";; esac
    [ "$capacity_value" -ge 1 ] && [ "$capacity_value" -le 100 ] || die "Capacity thresholds must be from 1 through 100."
done
fact selected_path "$capacity_path"
capacity_report() {
    capacity_kind=$1
    capacity_threshold=$2
    shift 2
    capacity_result=$("$@" 2>/dev/null)
    capacity_rc=$?
    [ "$capacity_rc" -eq 0 ] || return "$capacity_rc"
    capacity_metrics=$(printf '%s\n' "$capacity_result" | awk '
        NR>1 {
            for(i=4;i<=NF;i++) if($i ~ /^[0-9]+%$/ && $(i-1) ~ /^[0-9]+$/ && $(i-2) ~ /^[0-9]+$/ && $(i-3) ~ /^[0-9]+$/) {
                p=$i; sub(/%$/, "", p); print $(i-3), $(i-2), $(i-1), p; exit
            }
        }')
    [ -n "$capacity_metrics" ] || { finding Unknown "$capacity_kind" "The filesystem did not report parseable capacity metrics."; return 0; }
    printf '%s\n' "$capacity_metrics" | awk -v k="$capacity_kind" '{printf "%s_total=%s\n%s_used=%s\n%s_available=%s\n%s_percent_used=%s\n",k,$1,k,$2,k,$3,k,$4}'
    capacity_used=$(printf '%s\n' "$capacity_metrics" | awk '{print $4}')
    if [ "$capacity_used" -ge "$capacity_threshold" ]; then
        finding Warn "$capacity_kind" "Utilization is $capacity_used percent, meeting the selected $capacity_threshold percent threshold."
    else finding Pass "$capacity_kind" "Utilization is below the selected threshold."; fi
}
capture space_kib capacity_report space "$capacity_space" df -Pk "$capacity_path"
if df -Pi "$capacity_path" >/dev/null 2>&1; then
    capture inode_capacity capacity_report inodes "$capacity_inode" df -Pi "$capacity_path"
else finding Unknown inode_capacity "This df implementation or filesystem does not provide POSIX inode statistics."; fi
if [ -r "$ROOT_FS/proc/self/mounts" ]; then
    capacity_mounts() {
        awk '{
            state="unknown"; n=split($4,o,",");
            for(i=1;i<=n;i++) {if(o[i]=="ro") state="read-only"; if(o[i]=="rw") state="read-write"}
            print "target=" $2, "type=" $3, "state=" state
        }' "$ROOT_FS/proc/self/mounts"
    }
    capture mount_states capacity_mounts
else finding Unknown mount_states "Mount information is unavailable."; fi
finding Info capacity_scope "Capacity thresholds apply to the filesystem containing --path. Mount sources and credential-bearing options are excluded."

finish
