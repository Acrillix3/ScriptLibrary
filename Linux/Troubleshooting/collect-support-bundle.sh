#!/bin/sh
# What it does
# Build a private support report containing selected system, storage, network, service, and package metadata.
# Available flags
# --help; --output-dir DIRECTORY; --include-network yes|no (default yes); --include-packages yes|no (default yes); --package-limit COUNT (default 200, maximum 1000).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=collect-support-bundle
DESCRIPTION='Build a private support report containing selected system, storage, network, service, and package metadata.'
FLAGS='--include-network yes|no (default yes); --include-packages yes|no (default yes); --package-limit COUNT (default 200, maximum 1000).'
OPTIONS='include-network include-packages package-limit'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

bundle_network=$(arg include-network yes)
bundle_packages=$(arg include-packages yes)
bundle_limit=$(arg package-limit 200)
case "$bundle_network:$bundle_packages" in yes:yes|yes:no|no:yes|no:no) ;; *) die "include-network and include-packages accept yes or no.";; esac
case "$bundle_limit" in ''|*[!0-9]*) die "package-limit must be an integer from 1 through 1000.";; esac
[ "$bundle_limit" -ge 1 ] && [ "$bundle_limit" -le 1000 ] || die "package-limit must be from 1 through 1000."
capture kernel uname -srm
fact operating_system "$OS_ID $OS_VERSION"
fact init_system "$INIT_SYSTEM"
if [ -r "$ROOT_FS/proc/meminfo" ]; then
    bundle_memory() { awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/ {print}' "$ROOT_FS/proc/meminfo"; }
    capture memory bundle_memory
fi
bundle_space() {
    bundle_df=$(df -Pk / 2>/dev/null)
    bundle_df_rc=$?
    [ "$bundle_df_rc" -eq 0 ] || return "$bundle_df_rc"
    printf '%s\n' "$bundle_df" | awk 'NR>1 {
        for(i=4;i<=NF;i++) if($i ~ /^[0-9]+%$/ && $(i-1) ~ /^[0-9]+$/) {
            print "root_total_kib=" $(i-3), "root_used_kib=" $(i-2), "root_available_kib=" $(i-1), "root_used=" $i; exit
        }
    }'
}
capture root_capacity bundle_space
if [ "$bundle_network" = yes ]; then
    if have ip; then
        capture interface_addresses ip -o address show
        capture routes ip route show
    else finding Unknown network "The ip utility is unavailable."; fi
    if [ -r "$ROOT_FS/etc/resolv.conf" ]; then
        bundle_dns() { awk '$1=="nameserver" || $1=="search" || $1=="domain" {print}' "$ROOT_FS/etc/resolv.conf"; }
        capture resolver_metadata bundle_dns
    fi
fi
if [ "$INIT_SYSTEM" = systemd ] && have systemctl; then
    bundle_services() {
        bundle_failed=$(systemctl list-units --state=failed --no-legend --plain --no-pager 2>/dev/null)
        bundle_failed_rc=$?
        [ "$bundle_failed_rc" -eq 0 ] || return "$bundle_failed_rc"
        printf '%s\n' "$bundle_failed" | awk 'NF>=4 {print $1, $2, $3, $4}'
    }
    capture failed_services bundle_services
elif [ "$INIT_SYSTEM" = openrc ] && have rc-status; then
    capture service_states rc-status --all
else finding Unknown services "No supported service-state tool is available."; fi
if [ "$bundle_packages" = yes ]; then
    bundle_inventory() {
        case "$OS_FAMILY" in
            debian) bundle_package_data=$(dpkg-query -W 2>/dev/null); bundle_package_rc=$?;;
            rhel|fedora|amazon|suse) bundle_package_data=$(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null); bundle_package_rc=$?;;
            arch) bundle_package_data=$(pacman -Q 2>/dev/null); bundle_package_rc=$?;;
            alpine) bundle_package_data=$(apk info -v 2>/dev/null); bundle_package_rc=$?;;
            *) finding Unknown packages "No package adapter is defined for the detected operating system."; return 0;;
        esac
        [ "$bundle_package_rc" -eq 0 ] || return "$bundle_package_rc"
        printf '%s\n' "$bundle_package_data" | sort | awk -v n="$bundle_limit" 'NR<=n {print}'
        bundle_package_count=$(printf '%s\n' "$bundle_package_data" | awk 'NF {n++} END {print n+0}')
        fact installed_package_count "$bundle_package_count"
    }
    capture package_inventory bundle_inventory
fi
finding Info support_bundle "The report directory is the bundle. Raw logs, process arguments, environment variables, account databases, private keys, credentials, machine IDs, and configuration files are excluded. Review remaining host/network metadata before sharing."

finish
