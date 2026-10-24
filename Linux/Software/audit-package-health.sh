#!/bin/sh
# What it does
# Check package database consistency and optionally verify a selected installed package.
# Available flags
# --help; --output-dir DIRECTORY; --package NAME (optional integrity check).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-package-health
DESCRIPTION='Check package database consistency and optionally verify a selected installed package.'
FLAGS='--package NAME (optional integrity check).'
OPTIONS=package
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


pkg=$(arg package "")
case "$pkg" in -*|*[!A-Za-z0-9.+:_-]*) die "Invalid package name." ;; esac
case "$OS_FAMILY" in
 debian)
  if have dpkg; then capture database-audit dpkg --audit; if [ "$LAST_CAPTURE_RC" -eq 0 ] && [ -s "$REPORT_DIR/database-audit.txt" ]; then finding Warn package-state "dpkg reports unfinished or inconsistent package state."; fi; else finding Unknown database "dpkg is unavailable."; fi
  if have apt-get; then capture dependency-check apt-get -s check; else finding Unknown dependencies "apt-get is unavailable."; fi
  if [ -n "$pkg" ]; then
   if have dpkg; then dpkg-query -W "$pkg" >/dev/null 2>&1 || die "Selected package is not installed."; capture selected-package-integrity dpkg --verify "$pkg"; if [ "$LAST_CAPTURE_RC" -eq 0 ] && [ -s "$REPORT_DIR/selected-package-integrity.txt" ]; then finding Warn package-integrity "Package verification found differences. Review whether changes are approved."; fi; fi
  fi ;;
 rhel|fedora|amazon|suse)
  if have rpm; then if have rpmdb; then capture database-check rpmdb --verifydb; else finding Unknown database-check "rpmdb is unavailable."; fi; if [ -n "$pkg" ]; then rpm -q "$pkg" >/dev/null 2>&1 || die "Selected package is not installed."; capture selected-package-integrity rpm -V "$pkg"; if [ "$LAST_CAPTURE_RC" -ne 0 ]; then finding Warn package-integrity "Selected package has integrity differences or could not be verified; review captured evidence."; fi; fi; else finding Unknown database "rpm is unavailable."; fi
  if have dnf; then capture dependency-check dnf --cacheonly check; else finding Unknown dependencies "No cache-only DNF dependency check is available."; fi ;;
 arch)
  if have pacman; then capture database-check pacman -Dk; [ -z "$pkg" ] || capture selected-package-integrity pacman -Qkk "$pkg"; else finding Unknown database "pacman is unavailable."; fi ;;
 alpine)
  if have apk; then capture package-database apk info; finding Info integrity "apk inventory recorded; no broad apk audit is run because it can expose arbitrary filesystem paths."; else finding Unknown database "apk is unavailable."; fi
  [ -z "$pkg" ] || capture selected-package-files apk info -L "$pkg" ;;
 *) finding Unknown adapter "Unsupported package manager family." ;;
esac
finding Info interpretation "Review captured exit codes and output. Empty output only means that command found no reportable issue; it does not prove all installed files are healthy."

finish
