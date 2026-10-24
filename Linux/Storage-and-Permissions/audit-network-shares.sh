#!/bin/sh
# What it does
# Inspect selected Samba security settings, NFS export flags, and mounted network-share types without exposing passwords.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-network-shares
DESCRIPTION='Inspect selected Samba security settings, NFS export flags, and mounted network-share types without exposing passwords.'
FLAGS='No script-specific flags.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

share_samba() {
    share_smb=$(testparm -s 2>/dev/null)
    share_smb_rc=$?
    [ "$share_smb_rc" -eq 0 ] || return "$share_smb_rc"
    printf '%s\n' "$share_smb" | awk '
        /^\[/ {print; next}
        /^[[:space:]]*(path|read only|guest ok|guest only|browseable|valid users|write list|force user|force group|server min protocol|server max protocol|smb encrypt|security|map to guest|restrict anonymous)[[:space:]]*=/ {print}
    '
    if printf '%s\n' "$share_smb" | grep -Eq '^[[:space:]]*guest ok[[:space:]]*=[[:space:]]*[Yy][Ee][Ss]'; then
        finding Warn samba_guest_access "At least one Samba share permits guest access; verify its intended permissions."
    fi
    if printf '%s\n' "$share_smb" | grep -Eq '^[[:space:]]*server min protocol[[:space:]]*=[[:space:]]*(NT1|LANMAN|CORE)'; then
        finding Warn samba_legacy_protocol "A legacy minimum SMB protocol is configured."
    fi
    share_paths=$(printf '%s\n' "$share_smb" | awk '
        /^[[:space:]]*path[[:space:]]*=/ {sub(/^[^=]*=[[:space:]]*/, ""); if(substr($0,1,1)=="/") print}
    ')
    printf '%s\n' "$share_paths" | while IFS= read -r share_path; do
        [ -n "$share_path" ] || continue
        case "$share_path" in *%*) printf 'dynamic_share_path_requires_review\n';; *) ls -ldn "$share_path" 2>/dev/null || printf 'share_path_metadata_unavailable\n';; esac
    done
}
if have testparm; then capture samba_share_settings share_samba
else finding Unknown samba "testparm is unavailable; Samba configuration has not been validated."; fi
share_nfs() {
    share_exports=$(exportfs -v 2>/dev/null)
    share_exports_rc=$?
    [ "$share_exports_rc" -eq 0 ] || return "$share_exports_rc"
    printf '%s\n' "$share_exports" | awk '
        /^[^[:space:]]/ {print "export_path=" $1}
        {
            text=$0; n=split(text,parts,/[(),[:space:]]+/)
            for(i=1;i<=n;i++) if(parts[i] ~ /^(rw|ro|root_squash|no_root_squash|all_squash|no_all_squash|secure|insecure|sync|async|subtree_check|no_subtree_check|sec=[A-Za-z0-9:]+)$/) print "export_option=" parts[i]
        }
    '
    if printf '%s\n' "$share_exports" | grep -Eq '[(,]no_root_squash[,)]'; then
        finding Warn nfs_root_squash "An export disables root squashing; review the client trust boundary."
    fi
    if printf '%s\n' "$share_exports" | grep -Eq '[(,]insecure[,)]'; then
        finding Warn nfs_source_ports "An export allows unprivileged source ports."
    fi
    [ -n "$share_exports" ] || finding Info nfs_exports "No active exports were returned; configured but inactive exports may still exist."
}
if have exportfs; then capture active_nfs_exports share_nfs
else finding Unknown nfs_exports "exportfs is unavailable or NFS server tooling is absent."; fi
if [ -r "$ROOT_FS/proc/self/mounts" ]; then
    share_mounts() { awk '$3 ~ /^(nfs|nfs4|cifs|smb3)$/ {print "target=" $2, "type=" $3}' "$ROOT_FS/proc/self/mounts"; }
    capture mounted_network_shares share_mounts
else finding Unknown mounted_shares "Mount metadata is unreadable."; fi
if have getenforce; then capture selinux_mode getenforce; fi
finding Info share_scope "Only whitelisted Samba settings and NFS flags are exported. Share passwords, mount credentials/options, user files, and key material are excluded. Effective client access still needs an authorized client-side test."

finish
