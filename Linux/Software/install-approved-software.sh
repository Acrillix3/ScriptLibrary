#!/bin/sh
# What it does
# Install a reviewed package manifest through the detected distribution package manager.
# Available flags
# --help; --output-dir DIRECTORY; --manifest PATH (required TSV: family and package); --profile NAME (report label, default approved).
# --apply; --dry-run; --defer-restarts (defer disruptive activation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.
# Shows a plan first; changes require --apply and restarts require separate confirmation.

SCRIPT_NAME=install-approved-software
DESCRIPTION='Install a reviewed package manifest through the detected distribution package manager.'
FLAGS='--manifest PATH (required TSV: family and package); --profile NAME (report label, default approved).'
OPTIONS='manifest profile'
MUTATING=true

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


manifest=$(arg manifest "")
profile=$(arg profile approved)
[ -n "$manifest" ] && [ -f "$manifest" ] && [ -r "$manifest" ] || die "Supply a readable --manifest with family<TAB>package rows."
case "$profile" in ""|*[!A-Za-z0-9_-]*) die "Invalid profile name." ;; esac
finding Info manifest-format "Use one OS family and one native package name per TSV row. Valid families: debian rhel fedora amazon suse arch alpine all. Comments begin with #."
install_packages "$profile" "$manifest"

finish
