#!/bin/sh
# What it does
# Audit configured repository identities, trust settings, and source entries without refreshing metadata.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-package-repositories
DESCRIPTION='Audit configured repository identities, trust settings, and source entries without refreshing metadata.'
FLAGS='No script-specific flags.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


repo_scan() {
 awk '
 function safeuri(s) { sub(/\/\/[^\/]*@/,"//[redacted]@",s); sub(/\?.*$/,"?[redacted]",s); return s }
 /^[ \t]*#/ || /^[ \t]*$/ {next}
 FILENAME ~ /\.repo$/ {
  if ($0 ~ /^[ \t]*\[/) {print FILENAME ": " $0}
  if ($0 ~ /^[ \t]*(gpgcheck|repo_gpgcheck|enabled)[ \t]*=/) {print FILENAME ": " $0}
  if ($0 ~ /^[ \t]*(baseurl|mirrorlist|metalink)[ \t]*=/) {s=$0; sub(/=.*/,"=[configured; URI omitted]",s); print FILENAME ": " s}
  if ($0 ~ /^[ \t]*(gpgcheck|repo_gpgcheck)[ \t]*=[ \t]*0/) {print "WARNING signature check disabled in " FILENAME}
  next
 }
 FILENAME ~ /\.sources$/ {
  if ($0 ~ /^(Types|Suites|Components|Enabled|Signed-By|Trusted|Allow-Insecure):/) {if ($0 ~ /BEGIN PGP/) next; print FILENAME ": " $0}
  if ($0 ~ /^URIs:/) {for (i=2;i<=NF;i++) print FILENAME ": URI " safeuri($i)}
  next
 }
 FILENAME ~ /\.list$/ && $1 ~ /^deb(-src)?$/ {
  line=$0; gsub(/\/\/[^\/[:space:]]*@/,"//[redacted]@",line); sub(/\?.*/,"?[redacted]",line); print FILENAME ": " line; next
 }
 {print FILENAME ": " safeuri($0)}
 ' "$@"
}
case "$OS_FAMILY" in
 debian)
  set --
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do [ -r "$f" ] && set -- "$@" "$f"; done
  if [ "$#" -gt 0 ]; then capture repository-settings repo_scan "$@"; else finding Unknown repositories "No readable APT sources."; fi
  finding Info review "Review Trusted: yes, trusted=yes, missing Signed-By, mixed Suites, duplicate URI/Suite/Components, and disabled sources. Missing Signed-By alone is not proof that signatures are disabled." ;;
 rhel|fedora|amazon|suse)
  set --
  for f in /etc/yum.repos.d/*.repo /etc/zypp/repos.d/*.repo; do [ -r "$f" ] && set -- "$@" "$f"; done
  if [ "$#" -gt 0 ]; then capture repository-settings repo_scan "$@"; else finding Unknown repositories "No readable repository files."; fi
  finding Info review "Review enabled repositories and both package and repository signature settings. Repository URLs are deliberately omitted." ;;
 arch)
  if [ -r /etc/pacman.conf ]; then capture repository-settings awk '/^[ \t]*\[/ || /^[ \t]*(SigLevel|LocalFileSigLevel|RemoteFileSigLevel|Include)[ \t]*=/ {print}' /etc/pacman.conf; else finding Unknown repositories "pacman.conf is unreadable."; fi
  finding Info review "Review Never/TrustAll signature settings and included mirror files. No package database synchronization is performed." ;;
 alpine)
  if [ -r /etc/apk/repositories ]; then capture repositories repo_scan /etc/apk/repositories; else finding Unknown repositories "apk repository configuration is unreadable."; fi
  if [ -d /etc/apk/keys ]; then capture signing-key-metadata ls -ld /etc/apk/keys; else finding Unknown keys "APK signing-key directory is unavailable."; fi ;;
 *) finding Unknown adapter "No approved repository adapter." ;;
esac
finding Info trust "No network refresh, repository modification, or signing-key import is performed. Reports require human review of duplicate or mixed sources."

finish
