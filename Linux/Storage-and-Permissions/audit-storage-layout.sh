#!/bin/sh
# What it does
# Inventory block-device topology, LVM thin/snapshot capacity, MD RAID, Btrfs, and ZFS where present.
# Available flags
# --help; --output-dir DIRECTORY; --path /PATH (default /; used for Btrfs inspection).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-storage-layout
DESCRIPTION='Inventory block-device topology, LVM thin/snapshot capacity, MD RAID, Btrfs, and ZFS where present.'
FLAGS='--path /PATH (default /; used for Btrfs inspection).'
OPTIONS=path
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

layout_path=$(arg path /)
case "$layout_path" in /*) ;; *) die "path must be absolute.";; esac
[ -d "$layout_path" ] || die "path must be an existing directory."
if have lsblk; then capture block_layout lsblk -o NAME,TYPE,SIZE,FSTYPE,RO,MOUNTPOINT
else finding Unknown block_layout "lsblk is unavailable."; fi
if have pvs; then capture physical_volumes pvs --readonly --noheadings -o pv_name,vg_name,pv_size,pv_free
else finding Unknown lvm_physical_volumes "LVM reporting tools are unavailable."; fi
if have vgs; then capture volume_groups vgs --readonly --noheadings -o vg_name,vg_size,vg_free,pv_count,lv_count; fi
if have lvs; then capture logical_volumes lvs --readonly --noheadings -a -o lv_name,vg_name,lv_attr,lv_size,origin,data_percent,metadata_percent; fi
if [ -r "$ROOT_FS/proc/mdstat" ]; then capture md_raid cat "$ROOT_FS/proc/mdstat"
else finding Unknown md_raid "MD RAID status is not exposed."; fi
if have btrfs; then
    layout_type=$(stat -f -c %T "$layout_path" 2>/dev/null)
    if [ "$layout_type" = btrfs ]; then
        capture btrfs_capacity btrfs filesystem usage "$layout_path"
        capture btrfs_subvolumes btrfs subvolume list "$layout_path"
    else finding Info btrfs_scope "The selected path is not identified as Btrfs; choose its mounted path with --path."; fi
else finding Unknown btrfs "Btrfs tooling is unavailable."; fi
if have zpool; then capture zpool_health zpool status -x
else finding Unknown zpool "ZFS pool tooling is unavailable."; fi
if have zfs; then capture zfs_datasets zfs list -t filesystem,volume,snapshot -o name,used,avail,refer,mountpoint; fi
finding Info layout_scope "Missing filesystem tools mean that storage technology is unassessed. Snapshot presence does not establish that backups exist or can be restored."

finish
