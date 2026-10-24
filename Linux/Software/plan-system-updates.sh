#!/bin/sh
# What it does
# Plan system updates using cached metadata, held packages, free space, and restart indicators.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags. Never installs or refreshes package indexes.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=plan-system-updates
DESCRIPTION='Plan system updates using cached metadata, held packages, free space, and restart indicators.'
FLAGS='No script-specific flags. Never installs or refreshes package indexes.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


capture space df -Pk / /var /boot
case "$OS_FAMILY" in
 debian)
  if have apt-get; then capture cached-upgrade-plan apt-get -s upgrade; else finding Unknown updates "apt-get is unavailable."; fi
  if have apt-mark; then capture held-packages apt-mark showhold; fi
  if [ -d /var/lib/apt/lists ]; then capture cache-metadata ls -ld /var/lib/apt/lists; fi ;;
 rhel|fedora|amazon)
  if have dnf; then dnf_cached_updates() { dnf --cacheonly check-update; update_rc=$?; [ "$update_rc" -eq 100 ] && return 0; return "$update_rc"; }; capture cached-update-list dnf_cached_updates; finding Info dnf-exit "DNF exit code 100 indicates updates are available; code 1 indicates an error.";
  elif have yum; then finding Unknown updates "Only yum is present; no verified cache-only adapter is used.";
  else finding Unknown updates "DNF is unavailable."; fi
  [ ! -d /var/cache/dnf ] || capture cache-metadata ls -ld /var/cache/dnf ;;
 suse)
  if have zypper; then capture cached-update-list zypper --no-refresh list-updates; capture package-locks zypper --no-refresh locks; else finding Unknown updates "zypper is unavailable."; fi ;;
 arch)
  if have pacman; then capture cached-update-list pacman -Qu; else finding Unknown updates "pacman is unavailable."; fi
  finding Warn arch-updates "Cached sync metadata may be stale. Perform a reviewed full system upgrade separately; this script never runs pacman -Sy." ;;
 alpine)
  if have apk; then capture cached-upgrade-plan apk --no-network upgrade --simulate; else finding Unknown updates "apk is unavailable."; fi ;;
 *) finding Unknown adapter "No approved update planning adapter." ;;
esac
if [ -e /run/reboot-required ]; then finding Warn restart "A reboot-required marker exists."; else finding Unknown restart "No universal restart verdict is available. Absence of a marker does not mean a restart is unnecessary."; fi
finding Info freshness "Plans depend on existing cached repository metadata and may omit newer updates. Package installers can restart services; no installation is performed."

finish
