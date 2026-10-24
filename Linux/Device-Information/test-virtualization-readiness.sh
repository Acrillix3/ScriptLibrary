#!/bin/sh
# What it does
# Check CPU virtualization hints, KVM availability and permissions, and IOMMU visibility.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=test-virtualization-readiness
DESCRIPTION='Check CPU virtualization hints, KVM availability and permissions, and IOMMU visibility.'
FLAGS='No script-specific flags.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

virt_arch=$(uname -m 2>/dev/null)
fact architecture "$virt_arch"
case "$virt_arch" in
    x86_64|i?86)
        if [ -r "$ROOT_FS/proc/cpuinfo" ]; then
            if grep -Eq '(^|[[:space:]])(vmx|svm)([[:space:]]|$)' "$ROOT_FS/proc/cpuinfo"; then
                finding Pass cpu_virtualization "An Intel VT-x or AMD-V CPU flag is visible."
            else
                finding Unknown cpu_virtualization "No vmx/svm flag is visible; firmware settings or a hypervisor can hide the capability."
            fi
        else finding Unknown cpu_virtualization "CPU flags are not readable."; fi
        ;;
    aarch64|arm*) finding Unknown cpu_virtualization "ARM virtualization readiness depends on firmware and EL2 exposure; x86 CPU flags do not apply.";;
    *) finding Unknown cpu_virtualization "This architecture needs a platform-specific virtualization assessment.";;
esac
if [ -c /dev/kvm ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        finding Pass kvm_access "The current account has read and write access to /dev/kvm."
    else
        finding Warn kvm_access "/dev/kvm exists but the current account lacks read or write permission."
    fi
else finding Unknown kvm_access "No KVM device is visible; the kernel, firmware, container boundary, or nested-virtualization policy may be responsible."; fi
if [ -r "$ROOT_FS/proc/modules" ]; then
    virt_modules() { awk '$1 ~ /^kvm/ {print $1, "references=" $3}' "$ROOT_FS/proc/modules"; }
    capture kvm_modules virt_modules
fi
virt_iommu=0
for virt_group in "$ROOT_FS"/sys/kernel/iommu_groups/*; do
    [ -d "$virt_group" ] && virt_iommu=$((virt_iommu + 1))
done
fact visible_iommu_groups "$virt_iommu"
if [ "$virt_iommu" -eq 0 ]; then
    finding Unknown iommu "No IOMMU groups were visible; PCI passthrough readiness is unverified."
else
    finding Info iommu "IOMMU groups are visible; group isolation and individual device suitability still need review."
fi
finding Info readiness_scope "No VM is launched, no kernel module is loaded, and firmware settings are unchanged."

finish
