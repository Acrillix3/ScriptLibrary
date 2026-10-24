#!/bin/sh
# What it does
# Test a workstation against an explicit resource and capability baseline.
# Available flags
# --help; --output-dir DIRECTORY; --min-memory-mb NUMBER (default 4096); --min-root-free-mb NUMBER (default 10240); --required-commands comma-list (default curl,ssh); --dns-name HOST (optional).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=test-workstation-readiness
DESCRIPTION='Test a workstation against an explicit resource and capability baseline.'
FLAGS='--min-memory-mb NUMBER (default 4096); --min-root-free-mb NUMBER (default 10240); --required-commands comma-list (default curl,ssh); --dns-name HOST (optional).'
OPTIONS='min-memory-mb min-root-free-mb required-commands dns-name'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


memory_min=$(arg min-memory-mb 4096)
space_min=$(arg min-root-free-mb 10240)
commands=$(arg required-commands curl,ssh)
dns=$(arg dns-name "")
case "$memory_min:$space_min" in *[!0-9:]*|:*|*:) die "Resource thresholds must be nonnegative integers." ;; esac
case "$commands" in *[!A-Za-z0-9_,+.-]*|,*|*,|*,,*) die "Invalid required command list." ;; esac
case "$dns" in *[!A-Za-z0-9.-]*) die "Invalid DNS test name." ;; esac
if [ -r /proc/meminfo ]; then
 memory=$(awk '/^MemTotal:/ {printf "%.0f\n",$2/1024}' /proc/meminfo)
 if [ "$memory" -ge "$memory_min" ]; then finding Pass memory "$memory MiB meets $memory_min MiB."; else finding Fail memory "$memory MiB is below $memory_min MiB."; fi
else finding Unknown memory "No readable /proc/meminfo."; fi
space=$(df -Pk / 2>/dev/null | awk 'NR==2 {printf "%.0f\n",$4/1024}')
case "$space" in ""|*[!0-9]*) finding Unknown storage "Cannot determine free root filesystem space." ;;
 *) if [ "$space" -ge "$space_min" ]; then finding Pass storage "$space MiB free meets $space_min MiB."; else finding Fail storage "$space MiB free is below $space_min MiB."; fi ;; esac
oldifs=$IFS; IFS=,; set -- $commands; IFS=$oldifs
for command_name do if have "$command_name"; then finding Pass "command-$command_name" "Available."; else finding Fail "command-$command_name" "Required command is unavailable."; fi; done
if have ip; then capture network-addresses ip -brief address; capture default-routes ip route show default; else finding Unknown network "iproute2 is unavailable."; fi
if [ -n "$dns" ]; then
 if have getent; then capture dns-resolution getent ahosts "$dns"; elif have nslookup; then capture dns-resolution nslookup "$dns"; else finding Unknown dns "No supported DNS lookup utility."; fi
else finding Info dns "No external DNS probe requested."; fi
if [ "$INIT_SYSTEM" = systemd ] && have systemctl; then capture failed-services systemctl --failed --no-legend --no-pager; elif [ "$INIT_SYSTEM" = openrc ] && have rc-status; then capture service-state rc-status; else finding Unknown services "No supported init-state utility."; fi
finding Info baseline "Thresholds and command requirements are operator-selected. This is a readiness checklist, not a compliance certification."

finish
