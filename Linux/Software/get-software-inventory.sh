#!/bin/sh
# What it does
# Inventory installed native packages and optional Flatpak and Snap applications.
# Available flags
# --help; --output-dir DIRECTORY; --include-flatpak yes|no (default no); --include-snap yes|no (default no).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=get-software-inventory
DESCRIPTION='Inventory installed native packages and optional Flatpak and Snap applications.'
FLAGS='--include-flatpak yes|no (default no); --include-snap yes|no (default no).'
OPTIONS='include-flatpak include-snap'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


case "$OS_FAMILY" in
 debian) if have dpkg-query; then capture native-packages dpkg-query -W '-f=$binary:Package\t$Version\t$Architecture\n'; else finding Unknown packages "dpkg-query is unavailable."; fi ;;
 rhel|fedora|amazon|suse) if have rpm; then capture native-packages rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'; else finding Unknown packages "rpm is unavailable."; fi ;;
 arch) if have pacman; then capture native-packages pacman -Q; else finding Unknown packages "pacman is unavailable."; fi ;;
 alpine) if have apk; then capture native-packages apk info -v; else finding Unknown packages "apk is unavailable."; fi ;;
 *) finding Unknown packages "No approved package inventory adapter for this operating system." ;;
esac
for optional in flatpak snap; do
 enabled=$(arg "include-$optional" no)
 case "$enabled" in yes|no) ;; *) die "Optional application flags must be yes or no." ;; esac
 [ "$enabled" = yes ] || continue
 if have "$optional"; then
   if [ "$optional" = flatpak ]; then capture flatpak-packages flatpak list --columns=application,version,branch,installation; else capture snap-packages snap list; fi
 else finding Unknown "$optional" "Requested application manager is unavailable."; fi
done
finding Info scope "Package inventory is local; repositories are not refreshed. Command reports are bounded to 500 lines."

finish
