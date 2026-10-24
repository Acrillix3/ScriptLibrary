#!/bin/sh
# What it does
# Add one approved port rule to an already active UFW or firewalld policy while preserving management access.
# Available flags
# --help; --output-dir DIRECTORY; --port 1..65535 (required); --protocol tcp|udp (default tcp); --backend auto|ufw|firewalld; --zone NAME (firewalld required); --source CIDR (UFW optional).
# --apply; --dry-run; --defer-restarts (defer disruptive activation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.
# Shows a plan first; changes require --apply and restarts require separate confirmation.

SCRIPT_NAME=configure-endpoint-firewall
DESCRIPTION='Add one approved port rule to an already active UFW or firewalld policy while preserving management access.'
FLAGS='--port 1..65535 (required); --protocol tcp|udp (default tcp); --backend auto|ufw|firewalld; --zone NAME (firewalld required); --source CIDR (UFW optional).'
OPTIONS='port protocol backend zone source'
MUTATING=true

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


port=$(arg port "")
protocol=$(arg protocol tcp)
backend=$(arg backend auto)
zone=$(arg zone "")
source=$(arg source "")
case "$port" in ""|*[!0-9]*) die "Port must be numeric." ;; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "Port must be 1..65535."
case "$protocol" in tcp|udp) ;; *) die "Protocol must be tcp or udp." ;; esac
case "$backend" in auto|ufw|firewalld) ;; *) die "Invalid backend." ;; esac
case "$zone" in *[!A-Za-z0-9_-]*) die "Invalid zone name." ;; esac
case "$source" in *[!0-9A-Fa-f:./]*) die "Source must be a numeric address or CIDR." ;; esac
[ "$APPLY" -eq 0 ] || require_root
ufw_active=0; firewalld_active=0
if have ufw && ufw status 2>/dev/null | awk '$1=="Status:" && $2=="active" {found=1} END {exit !found}'; then ufw_active=1; fi
if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then firewalld_active=1; fi
[ $((ufw_active+firewalld_active)) -eq 1 ] || die "Exactly one supported active firewall manager is required. No backend will be enabled or flushed."
if [ "$backend" = auto ]; then if [ "$ufw_active" -eq 1 ]; then backend=ufw; else backend=firewalld; fi; fi
finding Info management "Only one additive allow rule is changed. Existing SSH rules, routes, defaults, and management policies are retained; no reload, flush, deny rule, or policy reset occurs."
case "$backend" in
 ufw)
  [ "$ufw_active" -eq 1 ] || die "UFW is not active."
  [ -z "$zone" ] || die "Zone applies only to firewalld."
  if [ -n "$source" ]; then change allow-port ufw allow proto "$protocol" from "$source" to any port "$port"; else change allow-port ufw allow "$port/$protocol"; fi
  capture firewall-verification ufw status numbered ;;
 firewalld)
  [ "$firewalld_active" -eq 1 ] || die "firewalld is not active."
  [ -n "$zone" ] || die "Select an explicit firewalld zone."
  [ -z "$source" ] || die "Source restriction is supported only by the UFW adapter; use a separately reviewed rich rule for firewalld."
  firewall-cmd --get-zones 2>/dev/null | tr ' ' '\n' | awk -v z="$zone" '$0==z {found=1} END {exit !found}' || die "Unknown firewalld zone."
  change allow-runtime firewall-cmd "--zone=$zone" "--add-port=$port/$protocol" || die "Runtime rule failed; permanent rule is not attempted."
  change allow-permanent firewall-cmd --permanent "--zone=$zone" "--add-port=$port/$protocol"
  if [ "$APPLY" -eq 1 ]; then capture runtime-rule firewall-cmd "--zone=$zone" "--query-port=$port/$protocol"; fi
  if [ "$APPLY" -eq 1 ]; then capture permanent-rule firewall-cmd --permanent "--zone=$zone" "--query-port=$port/$protocol"; fi ;;
esac
finding Info unsupported "Raw nftables, iptables, and inactive firewall managers require a reviewed backend-specific policy; this script does not replace them."

finish
