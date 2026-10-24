#!/bin/sh
# What it does
# Report reboot indicators, supported library/service restart hints, and running-kernel module availability without restarting anything.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=check-restart-requirements
DESCRIPTION='Report reboot indicators, supported library/service restart hints, and running-kernel module availability without restarting anything.'
FLAGS='No script-specific flags.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

restart_sources=0
restart_kernel=$(uname -r 2>/dev/null)
fact running_kernel "$restart_kernel"
if [ -d "$ROOT_FS/lib/modules/$restart_kernel" ] || [ -d "$ROOT_FS/usr/lib/modules/$restart_kernel" ]; then
    finding Info running_kernel_modules "A module tree matching the running kernel is present; this does not prove it is the newest installed kernel."
else
    finding Warn running_kernel_modules "No module tree matching the running kernel was found. A removed kernel package, container boundary, or an embedded kernel can explain this."
fi
for restart_marker in "$ROOT_FS/run/reboot-required" "$ROOT_FS/var/run/reboot-required"; do
    if [ -e "$restart_marker" ]; then
        restart_sources=$((restart_sources + 1))
        finding Warn reboot_indicator "The distribution's reboot-required marker exists."
        if [ -r "$restart_marker.pkgs" ]; then
            restart_packages() { awk 'NF==1 && $1 ~ /^[A-Za-z0-9][A-Za-z0-9+_.:-]*$/ {print; n++; if(n>=100) exit}' "$restart_marker.pkgs"; }
            capture reboot_requesting_packages restart_packages
        fi
        break
    fi
done
restart_needrestart() {
    restart_batch=$(needrestart -b -r l 2>/dev/null)
    restart_batch_rc=$?
    [ "$restart_batch_rc" -eq 0 ] || return "$restart_batch_rc"
    printf '%s\n' "$restart_batch" | awk '/^NEEDRESTART-(KCUR|KEXP|KSTA|SVC|UCSTA|UCEXP|CONT|SESS):/ {print}'
    if printf '%s\n' "$restart_batch" | grep -Eq '^NEEDRESTART-(SVC|CONT|SESS):'; then
        finding Warn service_restart_candidates "needrestart listed services, containers, or sessions using old components; no restart was requested."
    fi
    if printf '%s\n' "$restart_batch" | grep -Eq '^NEEDRESTART-KSTA:[[:space:]]*[23]'; then
        finding Warn kernel_restart_candidate "needrestart reports an outdated-kernel candidate."
    fi
    finding Info needrestart_scope "needrestart ran in batch list-only mode; its coverage depends on installed hooks, permissions, and supported interpreters."
}
if have needrestart; then
    restart_sources=$((restart_sources + 1))
    capture library_restart_hints restart_needrestart
fi
restart_rpm_check() {
    needs-restarting -r >/dev/null 2>&1
    restart_rpm_rc=$?
    if [ "$restart_rpm_rc" -eq 0 ]; then
        finding Info rpm_reboot_check "needs-restarting -r does not currently recommend a reboot."
    elif [ "$restart_rpm_rc" -eq 1 ]; then
        finding Warn rpm_reboot_check "needs-restarting -r recommends a reboot."
    else
        finding Unknown rpm_reboot_check "The RPM reboot check failed or this tool's interface differs."
    fi
}
case "$OS_FAMILY" in
    rhel|fedora|amazon)
        if have needs-restarting; then
            restart_sources=$((restart_sources + 1))
            capture rpm_reboot_requirement restart_rpm_check
        else finding Unknown rpm_reboot_check "The standalone needs-restarting tool is unavailable; no package-manager operation was invoked."; fi
        ;;
esac
if [ "$OS_FAMILY" = suse ] && have zypper; then
    restart_sources=$((restart_sources + 1))
    restart_suse() {
        restart_zypper=$(zypper --non-interactive ps -s 2>/dev/null)
        restart_zypper_rc=$?
        [ "$restart_zypper_rc" -eq 0 ] || return "$restart_zypper_rc"
        printf '%s\n' "$restart_zypper" | awk -F'|' 'NF>=6 && $1 ~ /[0-9]/ {s=$NF; gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); if(s ~ /^[A-Za-z0-9_.@:-]+$/) print "service_restart_candidate=" s}'
        finding Info suse_restart_scope "zypper ps -s metadata was checked. An empty list is not a complete reboot assessment."
    }
    capture suse_service_restart_hints restart_suse
fi
[ "$restart_sources" -gt 0 ] || finding Unknown restart_requirement "No supported distribution reboot or library-restart indicator was available. Absence of a marker is not proof that a reboot is unnecessary."
finding Info restart_policy "This script never stops or restarts a service, container, session, or computer."

finish
