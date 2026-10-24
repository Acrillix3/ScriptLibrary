#!/bin/sh
# What it does
# Audit local account IDs, account state, home directories, and local versus NSS identities.
# Available flags
# --help; --output-dir DIRECTORY; --user NAME (optional detailed account state).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-users-and-groups
DESCRIPTION='Audit local account IDs, account state, home directories, and local versus NSS identities.'
FLAGS='--user NAME (optional detailed account state).'
OPTIONS=user
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


selected=$(arg user "")
case "$selected" in *[!A-Za-z0-9_.-]*) die "Invalid user name." ;; esac
local_users() {
 awk -F: '{print $1 "\tuid=" $3 "\tgid=" $4 "\thome=" $6 "\tshell=" $7; u[$3]=u[$3] " " $1; c[$3]++; n[$1]++}
 END {for(id in c) if(c[id]>1) print "DUPLICATE_UID " id u[id]; for(name in n) if(n[name]>1) print "DUPLICATE_NAME " name}' /etc/passwd
}
if [ -r /etc/passwd ]; then capture local-accounts local_users; else finding Unknown local-accounts "Local passwd database is unreadable."; fi
if [ -r /etc/group ]; then capture local-groups awk -F: '{print $1 "\tgid=" $3 "\tmembers=" $4; g[$3]=g[$3] " " $1; c[$3]++} END {for(id in c) if(c[id]>1) print "DUPLICATE_GID " id g[id]}' /etc/group; fi
if have getent; then
 nss_count=$(getent passwd 2>/dev/null | wc -l | tr -d ' ')
 fact nss_enumerated_accounts "$nss_count"
 finding Info nss "NSS enumeration may be disabled for directory accounts; count is not an authoritative directory inventory."
else finding Unknown nss "getent is unavailable."; fi
if [ -n "$selected" ]; then
 if ! awk -F: -v u="$selected" '$1==u {found=1} END {exit !found}' /etc/passwd; then finding Unknown selected-user "Selected user is not in the local passwd database; local lock/expiry checks skipped.";
 else
  if have passwd; then capture account-lock-state passwd -S "$selected"; else finding Unknown lock-state "passwd status mode is unavailable."; fi
  if have chage; then capture account-expiry chage -l "$selected"; else finding Unknown expiry "chage is unavailable."; fi
  if have id; then capture account-membership id "$selected"; fi
 fi
fi
finding Info privacy "Password fields, shadow entries, and GECOS comments are excluded."

finish
