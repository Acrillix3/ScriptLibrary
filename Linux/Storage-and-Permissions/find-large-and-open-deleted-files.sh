#!/bin/sh
# What it does
# Find large files within a bounded directory scan and inventory deleted files still held open.
# Available flags
# --help; --output-dir DIRECTORY; --path /PATH (default /var/log); --minimum-mib MIB (default 100); --max-depth DEPTH (default 4, maximum 8); --limit COUNT (default 50, maximum 200); --timeout-seconds SECONDS (default 30, maximum 120).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=find-large-and-open-deleted-files
DESCRIPTION='Find large files within a bounded directory scan and inventory deleted files still held open.'
FLAGS='--path /PATH (default /var/log); --minimum-mib MIB (default 100); --max-depth DEPTH (default 4, maximum 8); --limit COUNT (default 50, maximum 200); --timeout-seconds SECONDS (default 30, maximum 120).'
OPTIONS='path minimum-mib max-depth limit timeout-seconds'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

large_path=$(arg path /var/log)
large_min=$(arg minimum-mib 100)
large_depth=$(arg max-depth 4)
large_limit=$(arg limit 50)
large_timeout=$(arg timeout-seconds 30)
case "$large_path" in /*) ;; *) die "path must be absolute.";; esac
[ -d "$large_path" ] || die "path must be an existing directory."
for large_value in "$large_min" "$large_depth" "$large_limit" "$large_timeout"; do
    case "$large_value" in ''|*[!0-9]*) die "Numeric flags require positive integers.";; esac
    [ "$large_value" -gt 0 ] || die "Numeric flags must be greater than zero."
done
[ "$large_min" -le 1048576 ] || die "minimum-mib cannot exceed 1048576."
[ "$large_depth" -le 8 ] || die "max-depth cannot exceed 8."
[ "$large_limit" -le 200 ] || die "limit cannot exceed 200."
[ "$large_timeout" -le 120 ] || die "timeout-seconds cannot exceed 120."
fact scan_path "$large_path"
fact minimum_mib "$large_min"
fact maximum_depth "$large_depth"
if have timeout && find --help 2>&1 | grep -q maxdepth; then
    large_temp="$REPORT_DIR/.large-file-scan"
    timeout "$large_timeout" find "$large_path" -xdev -maxdepth "$large_depth" -type f -size +"$((large_min * 2048))" -exec du -k '{}' + > "$large_temp" 2>/dev/null
    large_rc=$?
    large_results() { sort -nr "$large_temp" | awk -v n="$large_limit" 'NR<=n {print}'; }
    capture large_files_kib large_results
    large_rows=$(awk 'END {print NR+0}' "$large_temp")
    rm -f "$large_temp"
    if [ "$large_rc" -eq 124 ] || [ "$large_rc" -eq 137 ]; then
        finding Warn large_files "The scan timed out; only completed results are shown."
    elif [ "$large_rc" -ne 0 ]; then
        finding Unknown large_files "The scan was incomplete because of permissions or a command error."
    elif [ "$large_rows" -eq 0 ]; then
        finding Info large_files "No files above the threshold were found within the selected directory, depth, and filesystem."
    else finding Info large_files "Found $large_rows matching files; at most $large_limit entries are shown, ordered by allocated KiB."; fi
else
    finding Unknown large_files "A timeout command and find -maxdepth support are required for a bounded scan."
fi
if have lsof; then
    large_deleted() {
        large_open=$(lsof -nP +L1 -Fpftsn 2>/dev/null)
        large_open_rc=$?
        if [ "$large_open_rc" -eq 0 ]; then
            printf '%s\n' "$large_open"
        elif [ "$large_open_rc" -eq 1 ] && [ -z "$large_open" ]; then
            finding Unknown open_deleted_files "No deleted-open files were visible, or lsof could not inspect processes; restricted visibility cannot establish absence."
        else return "$large_open_rc"; fi
    }
    capture open_deleted_files large_deleted
else finding Unknown open_deleted_files "lsof is unavailable."; fi
finding Info scope "The scan stays on one filesystem and does not follow directory symlinks. No file is deleted or process restarted; inspect process ownership before remediation."

finish
