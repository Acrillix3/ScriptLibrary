#!/bin/sh
# What it does
# Summarize kernel error classes for a selected boot and list crash metadata without exporting raw messages or dumps.
# Available flags
# --help; --output-dir DIRECTORY; --boot current|previous (default current); --entries COUNT (default 1000, maximum 10000).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-boot-and-kernel-errors
DESCRIPTION='Summarize kernel error classes for a selected boot and list crash metadata without exporting raw messages or dumps.'
FLAGS='--boot current|previous (default current); --entries COUNT (default 1000, maximum 10000).'
OPTIONS='boot entries'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

boot_choice=$(arg boot current)
boot_entries=$(arg entries 1000)
case "$boot_choice" in current) boot_index=0;; previous) boot_index=-1;; *) die "boot must be current or previous.";; esac
case "$boot_entries" in ''|*[!0-9]*) die "entries must be an integer from 1 through 10000.";; esac
[ "$boot_entries" -ge 1 ] && [ "$boot_entries" -le 10000 ] || die "entries must be from 1 through 10000."
fact selected_boot "$boot_choice"
boot_summarize() {
    if [ "$1" = journal ]; then
        boot_text=$(journalctl -q -k -b "$boot_index" --no-pager -n "$boot_entries" -o cat 2>/dev/null)
        boot_rc=$?
    else
        boot_text=$(dmesg 2>/dev/null)
        boot_rc=$?
        boot_text=$(printf '%s\n' "$boot_text" | tail -n "$boot_entries")
    fi
    [ "$boot_rc" -eq 0 ] || return "$boot_rc"
    [ -n "$boot_text" ] || { finding Unknown kernel_messages "No accessible kernel entries were returned for the selected boot."; return 0; }
    printf '%s\n' "$boot_text" | awk '
        {s=tolower($0); records++}
        s ~ /out of memory|oom-kill|oom_reaper|killed process/ {oom++}
        s ~ /kernel panic|not syncing|oops:|bug:/ {panic++}
        s ~ /i\/o error|buffer i\/o|blk_update_request.*error|filesystem.*error|ext4-fs error|xfs.*corrupt|btrfs.*error/ {io++}
        s ~ /machine check|hardware error|edac.*error|uncorrected.*error/ {hardware++}
        s ~ /segfault|general protection fault/ {fault++}
        s ~ /firmware/ && s ~ /failed|missing|not found/ {firmware++}
        END {
            printf "sampled_entries=%d\noom_candidates=%d\npanic_oops_candidates=%d\nio_filesystem_candidates=%d\nhardware_candidates=%d\nprocess_fault_candidates=%d\nfirmware_candidates=%d\n", records,oom,panic,io,hardware,fault,firmware
        }
    '
    boot_matches=$(printf '%s\n' "$boot_text" | awk '{s=tolower($0); if(s ~ /out of memory|oom-kill|kernel panic|not syncing|oops:|i\/o error|hardware error|segfault|general protection fault|ext4-fs error/) n++} END {print n+0}')
    if [ "$boot_matches" -gt 0 ]; then
        finding Warn kernel_error_candidates "Recognized error patterns appear in the bounded sample; investigate locally using the protected logs."
    else finding Info kernel_error_candidates "No selected error patterns matched the bounded accessible sample; this does not establish a clean boot."; fi
}
if have journalctl; then
    capture kernel_error_counts boot_summarize journal
    if [ "$LAST_CAPTURE_RC" -ne 0 ] && [ "$boot_choice" = current ] && have dmesg; then
        capture kernel_error_counts_fallback boot_summarize dmesg
    fi
    capture recent_boot_metadata journalctl --list-boots --no-pager -n 5
elif [ "$boot_choice" = current ] && have dmesg; then
    capture kernel_error_counts boot_summarize dmesg
else finding Unknown kernel_errors "No accessible backend can inspect the selected boot."; fi
if [ -r "$ROOT_FS/proc/sys/kernel/tainted" ]; then
    fact kernel_taint_bitmask "$(cat "$ROOT_FS/proc/sys/kernel/tainted" 2>/dev/null)"
fi
if have coredumpctl; then capture recent_crash_metadata coredumpctl --no-pager --no-legend --since "7 days ago" list
else finding Unknown crash_metadata "coredumpctl is unavailable; other crash collection systems may be in use."; fi
finding Info log_scope "Log access can be restricted. Pattern counts are diagnostic leads, not root-cause findings. Raw log text, stack traces, command lines, core dumps, and crash file contents are excluded."

finish
