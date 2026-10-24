#!/bin/sh
# What it does
# Audit privileged group membership and sudo/doas policy metadata without exposing policy command arguments.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-elevated-access
DESCRIPTION='Audit privileged group membership and sudo/doas policy metadata without exposing policy command arguments.'
FLAGS='No script-specific flags.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


if have getent; then
 for group in root sudo wheel admin docker lxd disk; do
  line=$(getent group "$group" 2>/dev/null)
  [ -z "$line" ] || fact "group_$group" "$(printf '%s\n' "$line" | awk -F: '{print "gid=" $3 " members=" $4}')"
 done
else finding Unknown groups "getent is unavailable."; fi
set --
for f in /etc/sudoers /etc/sudoers.d/* /etc/doas.conf; do
 [ -f "$f" ] || continue
 set -- "$@" "$f"
 if [ -r "$f" ]; then
  count=$(awk '/^[ \t]*#/ {next} /NOPASSWD/ {n++} END {print n+0}' "$f")
  fact "nopasswd_lines_$f" "$count"
 else finding Unknown policy-access "A policy file cannot be read: $f"; fi
done
[ "$#" -eq 0 ] || capture policy-file-metadata ls -ld "$@"
if have visudo; then capture sudo-syntax visudo -c; else finding Unknown sudo-syntax "visudo is unavailable; sudo syntax is not verified."; fi
if have doas; then finding Info doas "doas is installed. Policy text is deliberately excluded; review /etc/doas.conf locally."; fi
finding Warn privilege-review "docker, lxd, disk, UID 0 accounts, and passwordless rules may confer broad privileges. Membership alone is not a complete effective-authorization audit."
if [ -r /etc/passwd ]; then capture uid-zero-accounts awk -F: '$3==0 {print $1}' /etc/passwd; fi

finish
