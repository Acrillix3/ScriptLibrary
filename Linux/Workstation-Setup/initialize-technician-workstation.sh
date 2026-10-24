#!/bin/sh
# What it does
# Plan or install an approved technician support-tool profile using native distribution packages.
# Available flags
# --help; --output-dir DIRECTORY; --profile minimal|technician (default minimal). Review the generated manifest before --apply.
# --apply; --dry-run; --defer-restarts (defer disruptive activation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.
# Shows a plan first; changes require --apply and restarts require separate confirmation.

SCRIPT_NAME=initialize-technician-workstation
DESCRIPTION='Plan or install an approved technician support-tool profile using native distribution packages.'
FLAGS='--profile minimal|technician (default minimal). Review the generated manifest before --apply.'
OPTIONS=profile
MUTATING=true

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


profile=$(arg profile minimal)
case "$profile" in minimal|technician) ;; *) die "Profile must be minimal or technician." ;; esac
manifest="$REPORT_DIR/technician-packages.tsv"
case "$OS_FAMILY" in
 debian) packages="curl dnsutils iproute2 openssh-client"; [ "$profile" = minimal ] || packages="$packages smartmontools lsof traceroute tcpdump" ;;
 rhel|fedora|amazon) packages="curl bind-utils iproute openssh-clients"; [ "$profile" = minimal ] || packages="$packages smartmontools lsof traceroute tcpdump" ;;
 suse) packages="curl bind-utils iproute2 openssh-clients"; [ "$profile" = minimal ] || packages="$packages smartmontools lsof traceroute tcpdump" ;;
 arch) packages="curl bind iproute2 openssh"; [ "$profile" = minimal ] || packages="$packages smartmontools lsof traceroute tcpdump" ;;
 alpine) packages="curl bind-tools iproute2 openssh-client"; [ "$profile" = minimal ] || packages="$packages smartmontools lsof traceroute tcpdump" ;;
 *) die "No approved workstation package profile for this OS family." ;;
esac
for package in $packages; do printf '%s\t%s\n' "$OS_FAMILY" "$package"; done > "$manifest"
finding Info profile "Support profile $profile. Native repository package availability and versions are verified by the package manager; no third-party repository is added."
install_packages "$profile" "$manifest"

finish
