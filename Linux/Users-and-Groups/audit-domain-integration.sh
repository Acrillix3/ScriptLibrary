#!/bin/sh
# What it does
# Audit realmd, SSSD, winbind, Kerberos prerequisites, and domain identity resolution without rejoining.
# Available flags
# --help; --output-dir DIRECTORY; --identity NAME (optional directory identity to resolve); --domain NAME (optional DNS SRV lookup).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-domain-integration
DESCRIPTION='Audit realmd, SSSD, winbind, Kerberos prerequisites, and domain identity resolution without rejoining.'
FLAGS='--identity NAME (optional directory identity to resolve); --domain NAME (optional DNS SRV lookup).'
OPTIONS='identity domain'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


identity=$(arg identity "")
domain=$(arg domain "")
case "$identity" in *[!A-Za-z0-9_.@\\-]*) die "Invalid identity name." ;; esac
case "$domain" in *[!A-Za-z0-9.-]*) die "Invalid DNS domain name." ;; esac
if have realm; then capture joined-realms realm list; else finding Unknown realmd "realmd is unavailable; another join method may be in use."; fi
if have sssctl; then capture sssd-domain-list sssctl domain-list; else finding Unknown sssd "sssctl is unavailable."; fi
if have wbinfo; then capture winbind-trust-test wbinfo -t; capture winbind-domain wbinfo --own-domain; else finding Unknown winbind "wbinfo is unavailable."; fi
if have klist; then capture kerberos-ticket-metadata klist; else finding Unknown kerberos "klist is unavailable. No ticket or keytab contents are collected."; fi
if [ -n "$identity" ]; then
 if have id; then capture selected-identity id "$identity"; else finding Unknown resolution "id is unavailable."; fi
fi
if [ -n "$domain" ]; then
 if have dig; then capture ldap-discovery dig +time=2 +tries=1 +short SRV "_ldap._tcp.$domain"; capture kerberos-discovery dig +time=2 +tries=1 +short SRV "_kerberos._tcp.$domain";
 else finding Unknown dns-discovery "dig is unavailable."; fi
fi
if [ -r /etc/nsswitch.conf ]; then capture nss-integration awk '/^(passwd|group|hosts):/ {print}' /etc/nsswitch.conf; fi
finding Info scope "No SSSD configuration, keytab, Samba secrets, ticket material, domain credentials, rekey, or rejoin operation is collected or performed."

finish
