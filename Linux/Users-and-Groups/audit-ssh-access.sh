#!/bin/sh
# What it does
# Audit effective SSH access policy and selected public-key fingerprints and file permissions.
# Available flags
# --help; --output-dir DIRECTORY; --user NAME (optional local account); --client-address IP and --client-host HOST (both needed with user for Match evaluation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-ssh-access
DESCRIPTION='Audit effective SSH access policy and selected public-key fingerprints and file permissions.'
FLAGS='--user NAME (optional local account); --client-address IP and --client-host HOST (both needed with user for Match evaluation).'
OPTIONS='user client-address client-host'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


selected=$(arg user "")
address=$(arg client-address "")
clienthost=$(arg client-host "")
case "$selected" in *[!A-Za-z0-9_.-]*) die "Invalid user." ;; esac
case "$address$clienthost" in *[!A-Za-z0-9_.:%-]*) die "Invalid client context." ;; esac
sshd_bin=""
if have sshd; then sshd_bin=$(command -v sshd); elif [ -x /usr/sbin/sshd ]; then sshd_bin=/usr/sbin/sshd; fi
ssh_policy() {
 "$sshd_bin" "$@" > "$REPORT_DIR/sshd-effective-private" 2>/dev/null
 rc=$?
 [ "$rc" -eq 0 ] || return "$rc"
 awk '$1 ~ /^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|authenticationmethods|usepam|allowusers|allowgroups|denyusers|denygroups|authorizedkeysfile|strictmodes|maxauthtries)$/' "$REPORT_DIR/sshd-effective-private"
 rm -f "$REPORT_DIR/sshd-effective-private"
}
key_fingerprints() {
 ssh-keygen -l -f "$1" > "$REPORT_DIR/key-fingerprints-private" 2>/dev/null
 rc=$?
 [ "$rc" -eq 0 ] || return "$rc"
 awk '{print $1 " " $2 " " $NF}' "$REPORT_DIR/key-fingerprints-private"
 rm -f "$REPORT_DIR/key-fingerprints-private"
}
if [ -n "$sshd_bin" ]; then
 capture ssh-config-test "$sshd_bin" -t
 if [ -n "$selected" ] && [ -n "$address" ] && [ -n "$clienthost" ]; then capture effective-ssh-policy ssh_policy -T -C "user=$selected,host=$clienthost,addr=$address";
 else capture default-ssh-policy ssh_policy -T; finding Info match-rules "Default policy only. Supply user, client-address and client-host together to evaluate applicable Match rules."; fi
else finding Unknown sshd "OpenSSH server is unavailable."; fi
if [ -n "$selected" ]; then
 home=$(awk -F: -v u="$selected" '$1==u {print $6}' /etc/passwd)
 case "$home" in /*) ;; *) die "Selected local user has no valid absolute home directory." ;; esac
 [ "$home" != / ] || die "Root-home filesystem scan is refused."
 for f in "$home" "$home/.ssh" "$home/.ssh/authorized_keys"; do [ ! -e "$f" ] || capture ssh-file-metadata ls -ld "$f"; done
 if [ -f "$home/.ssh/authorized_keys" ] && [ -r "$home/.ssh/authorized_keys" ]; then
  if have ssh-keygen; then capture public-key-fingerprints key_fingerprints "$home/.ssh/authorized_keys"; else finding Unknown keys "ssh-keygen is unavailable."; fi
 else finding Unknown keys "No readable standard authorized_keys file. Custom AuthorizedKeysCommand or paths require separate review."; fi
fi
finding Info scope "Private keys, key comments, and authorized-key contents are excluded."

finish
