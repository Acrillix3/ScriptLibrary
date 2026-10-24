#!/bin/sh
# What it does
# Audit a selected tree for world-writable objects, unprotected writable directories, special executable bits, and root ACL metadata.
# Available flags
# --help; --output-dir DIRECTORY; --path /PATH (default /etc); --max-depth DEPTH (default 3, maximum 8); --limit COUNT (default 100, maximum 200); --timeout-seconds SECONDS (default 30, maximum 120).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-filesystem-permissions
DESCRIPTION='Audit a selected tree for world-writable objects, unprotected writable directories, special executable bits, and root ACL metadata.'
FLAGS='--path /PATH (default /etc); --max-depth DEPTH (default 3, maximum 8); --limit COUNT (default 100, maximum 200); --timeout-seconds SECONDS (default 30, maximum 120).'
OPTIONS='path max-depth limit timeout-seconds'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

perm_path=$(arg path /etc)
perm_depth=$(arg max-depth 3)
perm_limit=$(arg limit 100)
perm_timeout=$(arg timeout-seconds 30)
case "$perm_path" in /*) ;; *) die "path must be absolute.";; esac
[ -d "$perm_path" ] || die "path must be an existing directory."
for perm_value in "$perm_depth" "$perm_limit" "$perm_timeout"; do
    case "$perm_value" in ''|*[!0-9]*) die "Numeric flags require positive integers.";; esac
    [ "$perm_value" -gt 0 ] || die "Numeric flags must be greater than zero."
done
[ "$perm_depth" -le 8 ] && [ "$perm_limit" -le 200 ] && [ "$perm_timeout" -le 120 ] || die "Maximums are depth 8, limit 200, and timeout 120."
fact selected_path "$perm_path"
capture root_permissions ls -ldn "$perm_path"
if have getfacl; then capture root_acl getfacl -c -n "$perm_path"
else finding Unknown root_acl "getfacl is unavailable."; fi
if have timeout && find --help 2>&1 | grep -q maxdepth; then
    perm_scan() {
        perm_check=$1
        shift
        perm_temp="$REPORT_DIR/.permission-scan"
        timeout "$perm_timeout" find "$perm_path" -xdev -maxdepth "$perm_depth" "$@" -exec ls -ldn '{}' + > "$perm_temp" 2>/dev/null
        perm_rc=$?
        awk -v n="$perm_limit" 'NR<=n {print}' "$perm_temp"
        perm_count=$(awk 'END {print NR+0}' "$perm_temp")
        rm -f "$perm_temp"
        if [ "$perm_rc" -ne 0 ]; then
            finding Unknown "$perm_check" "Permission inventory is partial because of an access error, unsupported option, or timeout."
        elif [ "$perm_count" -gt 0 ]; then
            finding Warn "$perm_check" "Found $perm_count objects in scope; showing at most $perm_limit. Review whether each permission is intended."
        else finding Pass "$perm_check" "No matching objects were found in the selected bounded scope."; fi
    }
    capture world_writable perm_scan world_writable -perm -0002
    capture writable_directories_without_sticky perm_scan writable_directories_without_sticky -type d -perm -0002 ! -perm -1000
    capture setuid_setgid_files perm_scan setuid_setgid_files -type f '(' -perm -4000 -o -perm -2000 ')'
else finding Unknown permission_scan "A timeout command and find -maxdepth support are required for bounded scanning."; fi
finding Info permissions_scope "This is a DAC/ACL metadata audit, limited by the current account and selected depth. Special bits can be legitimate. No ownership, ACL, mode, or security label is changed."

finish
