#!/bin/sh
# What it does
# Check SELinux/AppArmor state, a selected path's label metadata, and bounded denial counts without disabling protection.
# Available flags
# --help; --output-dir DIRECTORY; --path /PATH (default /); --entries COUNT (default 1000, maximum 10000).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-security-policy-denials
DESCRIPTION='Check SELinux/AppArmor state, a selected path'"'"'s label metadata, and bounded denial counts without disabling protection.'
FLAGS='--path /PATH (default /); --entries COUNT (default 1000, maximum 10000).'
OPTIONS='path entries'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

policy_path=$(arg path /)
policy_entries=$(arg entries 1000)
case "$policy_path" in /*) ;; *) die "path must be absolute.";; esac
[ -e "$policy_path" ] || die "path does not exist."
case "$policy_entries" in ''|*[!0-9]*) die "entries must be an integer from 1 through 10000.";; esac
[ "$policy_entries" -ge 1 ] && [ "$policy_entries" -le 10000 ] || die "entries must be from 1 through 10000."
policy_detected=no
if have getenforce; then
    policy_detected=yes
    capture selinux_mode getenforce
    if have sestatus; then capture selinux_policy sestatus; fi
    capture selected_path_label ls -Zd "$policy_path"
fi
if [ -r "$ROOT_FS/sys/module/apparmor/parameters/enabled" ]; then
    policy_detected=yes
    fact apparmor_enabled "$(head -c 32 "$ROOT_FS/sys/module/apparmor/parameters/enabled" 2>/dev/null)"
fi
if have aa-status; then
    policy_detected=yes
    capture apparmor_status aa-status
fi
[ "$policy_detected" = yes ] || finding Unknown security_policy "Neither an SELinux status tool nor AppArmor state was available."
policy_denials() {
    policy_logs=$(journalctl -q -k -b --no-pager -n "$policy_entries" -o cat 2>/dev/null)
    policy_rc=$?
    [ "$policy_rc" -eq 0 ] || return "$policy_rc"
    [ -n "$policy_logs" ] || { finding Unknown denial_sample "No accessible kernel journal entries were returned."; return 0; }
    printf '%s\n' "$policy_logs" | awk '
        {s=tolower($0); count++}
        s ~ /avc:.*denied|type=avc.*denied/ {selinux++}
        s ~ /apparmor="denied"|apparmor=.*denied/ {apparmor++}
        END {printf "sampled_entries=%d\nselinux_denial_candidates=%d\napparmor_denial_candidates=%d\n",count,selinux,apparmor}
    '
    policy_matches=$(printf '%s\n' "$policy_logs" | awk '{s=tolower($0); if(s ~ /avc:.*denied|type=avc.*denied|apparmor="denied"|apparmor=.*denied/) n++} END {print n+0}')
    if [ "$policy_matches" -gt 0 ]; then
        finding Warn policy_denials "Denial candidates were found in the bounded kernel journal sample. Review labels and the intended access locally."
    else finding Info policy_denials "No selected denial patterns matched this sample; auditd/user-space denials and rotated logs are not covered."; fi
}
if have journalctl; then capture denial_counts policy_denials
else finding Unknown policy_denials "journalctl is unavailable; denial history has not been assessed."; fi
finding Info protection_scope "No enforcement mode, security profile, label, boolean, or policy is changed. Do not infer that absent or unreadable records mean access was permitted."

finish
