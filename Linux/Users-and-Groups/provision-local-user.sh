#!/bin/sh
# What it does
# Create a new local account with optional local groups, expiry, and one public SSH key.
# Available flags
# --help; --output-dir DIRECTORY; --user NAME (required); --groups GROUP1,GROUP2; --expires YYYY-MM-DD; --public-key PATH. Requires an unused /home/NAME; password remains locked.
# --apply; --dry-run; --defer-restarts (defer disruptive activation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.
# Shows a plan first; changes require --apply and restarts require separate confirmation.

SCRIPT_NAME=provision-local-user
DESCRIPTION='Create a new local account with optional local groups, expiry, and one public SSH key.'
FLAGS='--user NAME (required); --groups GROUP1,GROUP2; --expires YYYY-MM-DD; --public-key PATH. Requires an unused /home/NAME; password remains locked.'
OPTIONS='user groups expires public-key'
MUTATING=true

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


newuser=$(arg user "")
groups=$(arg groups "")
expires=$(arg expires "")
keyfile=$(arg public-key "")
case "$newuser" in ""|[!a-z_]*|*[!a-z0-9_-]*) die "Use a lowercase local user name beginning with a letter or underscore." ;; esac
[ "$(printf '%s' "$newuser" | wc -c)" -le 32 ] || die "User name is too long."
case "$groups" in *[!A-Za-z0-9_,.-]*|,*|*,|*,,*) die "Invalid group list." ;; esac
if [ -n "$expires" ]; then
 printf '%s\n' "$expires" | awk '/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ {ok=1} END {exit !ok}' || die "Expiry must be YYYY-MM-DD."
fi
if have getent; then getent passwd "$newuser" >/dev/null 2>&1 && die "The account already resolves through local or directory identity services."; else die "getent is required to avoid a local/directory name collision."; fi
home="/home/$newuser"
[ ! -e "$home" ] && [ ! -L "$home" ] || die "Requested home path already exists or is a symlink."
[ -d /home ] && [ ! -L /home ] || die "An existing non-symlink /home directory is required."
getent group "$newuser" >/dev/null 2>&1 && die "A group already uses this name; a private primary group cannot be created."
have useradd || die "The shadow useradd utility is required. Minimal Alpine installations must have the administrator-approved shadow package installed first."
have passwd || die "passwd is required."
if [ -n "$groups" ]; then
 oldifs=$IFS; IFS=,; set -- $groups; IFS=$oldifs
 for group do awk -F: -v g="$group" '$1==g {found=1} END {exit !found}' /etc/group || die "Every requested group must already exist locally."; done
fi
sanitized_key="$REPORT_DIR/approved-public-key"
if [ -n "$keyfile" ]; then
 [ -f "$keyfile" ] && [ -r "$keyfile" ] || die "Public key file is unreadable."
 awk 'NF {n++; if($1 !~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))$/ || $2 !~ /^[A-Za-z0-9+\/=]+$/) bad=1; print $1 " " $2} END {if(n!=1 || bad) exit 1}' "$keyfile" > "$sanitized_key" || die "Supply exactly one OpenSSH public key without authorized_keys options."
 have ssh-keygen || die "ssh-keygen is required to validate the public key."
 ssh-keygen -l -f "$sanitized_key" >/dev/null 2>&1 || die "Invalid public key."
fi
finding Info account-plan "Create local account $newuser using /bin/sh, a private primary group, a home directory, and a locked password."
[ "$APPLY" -eq 0 ] || require_root
set -- useradd -m -U -d "$home" -s /bin/sh
[ -z "$groups" ] || set -- "$@" -G "$groups"
[ -z "$expires" ] || set -- "$@" -e "$expires"
set -- "$@" "$newuser"
create_ok=0; if change create-local-user "$@"; then create_ok=1; fi
if [ "$APPLY" -eq 1 ] && [ "$create_ok" -eq 1 ]; then
 passwd -l "$newuser" >/dev/null 2>&1 || die "Account created but password lock failed; review immediately."
 actual_home=$(awk -F: -v u="$newuser" '$1==u {print $6}' /etc/passwd)
 [ "$actual_home" = "$home" ] && [ -d "$home" ] && [ ! -L "$home" ] || die "Account created but expected private home was not verified; key installation skipped."
 if [ -n "$keyfile" ]; then
  [ ! -e "$home/.ssh" ] && [ ! -L "$home/.ssh" ] || die "Existing .ssh path, including a skeleton profile directory, will not be modified."
  [ ! -e "$home/.ssh/authorized_keys" ] || die "Existing authorized_keys will not be overwritten."
  mkdir "$home/.ssh" && chmod 700 "$home/.ssh" || die "Cannot prepare SSH directory."
  cp "$sanitized_key" "$home/.ssh/authorized_keys" && chmod 600 "$home/.ssh/authorized_keys" && chown "$newuser" "$home/.ssh" "$home/.ssh/authorized_keys" || die "Account created but key installation failed."
 fi
 capture account-verification id "$newuser"
fi
finding Info scope "Existing accounts are never modified. Directory join, passwords, sudo rules and account deletion are outside this script."

finish
