#!/bin/sh
# What it does
# Plan a static IPv4 Ethernet profile cloned from the active NetworkManager profile, with separate activation confirmation.
# Available flags
# --help; --output-dir DIRECTORY; --backend networkmanager --interface NAME --connection EXISTING_UUID --profile NEW_NAME --address IPv4/PREFIX --gateway IPv4 --dns IPv4[,IPv4]; --apply still asks before activation; existing profiles are preserved.
# --apply; --dry-run; --defer-restarts (defer disruptive activation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.
# Shows a plan first; changes require --apply and restarts require separate confirmation.

SCRIPT_NAME=configure-static-network
DESCRIPTION='Plan a static IPv4 Ethernet profile cloned from the active NetworkManager profile, with separate activation confirmation.'
FLAGS='--backend networkmanager --interface NAME --connection EXISTING_UUID --profile NEW_NAME --address IPv4/PREFIX --gateway IPv4 --dns IPv4[,IPv4]; --apply still asks before activation; existing profiles are preserved.'
OPTIONS='backend interface connection profile address gateway dns'
MUTATING=true

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


backend=$(arg backend networkmanager)
iface=$(arg interface '')
source_uuid=$(arg connection '')
profile=$(arg profile '')
address=$(arg address '')
gateway=$(arg gateway '')
dns=$(arg dns '')
valid_ipv4() { printf '%s\n' "$1" | awk -F. 'NF!=4{exit 1} {for(i=1;i<=4;i++) if($i!~/^[0-9]+$/ || $i+0>255) exit 1}'; }
case "$iface" in ''|*[!A-Za-z0-9_.:-]*) die "Specify a valid --interface.";; esac
case "$source_uuid" in ''|*[!A-Fa-f0-9-]*) die "Specify the existing NetworkManager profile UUID.";; esac
case "$profile" in ''|-*|*[!A-Za-z0-9_.-]*) die "Specify a new simple --profile name.";; esac
case "$address" in */*/*) die "Address must contain one IPv4 prefix.";; */*) ip_address=$(printf '%s' "$address" | cut -d/ -f1); prefix=$(printf '%s' "$address" | cut -d/ -f2);; *) die "Address must include an IPv4 prefix."; esac
valid_ipv4 "$ip_address" || die "Invalid IPv4 address."
case "$prefix" in ''|*[!0-9]*) die "Invalid IPv4 prefix.";; esac
[ "$prefix" -ge 1 ] && [ "$prefix" -le 32 ] || die "IPv4 prefix must be 1-32."
valid_ipv4 "$gateway" || die "Invalid IPv4 gateway."
[ -n "$dns" ] || die "Specify --dns."
case "$dns" in ,*|*,|*,,*) die "DNS must not contain empty entries.";; esac
dns_valid=1
old_ifs=$IFS; IFS=,
for resolver in $dns; do valid_ipv4 "$resolver" || dns_valid=0; done
IFS=$old_ifs
[ "$dns_valid" = 1 ] || die "DNS must contain comma-separated IPv4 addresses."
fact proposed-interface "$iface"
fact proposed-address "$address"
fact proposed-gateway "$gateway"
fact proposed-dns "$dns"
if [ "$backend" != networkmanager ]; then
    finding Unknown backend "Only NetworkManager apply is implemented. Review this IPv4 plan in the active backend; no files were changed."
else
    have nmcli || die "NetworkManager nmcli is required."
    capture networkmanager-state nmcli general status
    [ "$LAST_CAPTURE_RC" = 0 ] || die "NetworkManager is unavailable."
    actual_uuid=$(nmcli -g GENERAL.CON-UUID device show "$iface" 2>/dev/null)
    [ "$actual_uuid" = "$source_uuid" ] || die "The selected existing UUID is not the active profile on this interface."
    source_type=$(nmcli -g connection.type connection show uuid "$source_uuid" 2>/dev/null)
    [ "$source_type" = 802-3-ethernet ] || die "Only a plain Ethernet profile is supported."
    controller=$(nmcli -g connection.master connection show uuid "$source_uuid" 2>/dev/null)
    auth=$(nmcli -g 802-1x.eap connection show uuid "$source_uuid" 2>/dev/null)
    [ -z "$controller" ] && [ -z "$auth" ] || die "Controller ports and 802.1X profiles require a separate reviewed procedure."
    if nmcli -g connection.uuid connection show id "$profile" >/dev/null 2>&1; then die "The new profile already exists; choose a unique name."; fi
    capture original-ipv4 nmcli -f connection.id,connection.uuid,connection.interface-name,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns connection show uuid "$source_uuid"
    finding Info rollback "Original profile remains unchanged. To return to it locally: nmcli connection up uuid $source_uuid ifname $iface"
    if [ "$APPLY" = 1 ]; then require_root; fi
    if change clone-original-profile nmcli connection clone uuid "$source_uuid" "$profile"; then
        if change configure-static-profile nmcli connection modify id "$profile" connection.autoconnect no ipv4.method manual ipv4.addresses "$address" ipv4.gateway "$gateway" ipv4.dns "$dns" ipv4.ignore-auto-dns yes; then
            if [ "$APPLY" = 1 ]; then
                finding Warn activation "New cloned profile is saved with autoconnect disabled; activation may disconnect this session. Original IPv6, MTU, and Ethernet settings are preserved."
                capture new-profile nmcli -f connection.id,connection.uuid,connection.autoconnect,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv6.method connection show id "$profile"
                if confirm_disruption "Activate the new network profile now? This may disconnect remote access."; then
                    change activate-static-profile nmcli --wait 30 connection up id "$profile" ifname "$iface"
                    capture active-ipv4 nmcli -f GENERAL.DEVICE,GENERAL.CON-UUID,IP4.ADDRESS,IP4.GATEWAY,IP4.DNS device show "$iface"
                fi
            fi
        else
            finding Fail profile-staging "Modification failed; the cloned profile may retain the original autoconnect setting. Activation was not requested. Review and remove only the new named profile locally if appropriate."
        fi
    fi
fi

finish
