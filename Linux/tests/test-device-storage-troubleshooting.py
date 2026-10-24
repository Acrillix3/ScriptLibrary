"""Syntax and command-fixture tests; no production Linux tools are executed."""
import json
import shlex
import subprocess
import argparse
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
parser.add_argument('--shell', default='/bin/bash', help='Bash is used only by this fixture runner; production scripts use /bin/sh.')
args = parser.parse_args()
BASE = args.root.resolve()
BASH = Path(args.shell)
GROUPS = ("Device-Information", "Storage-and-Permissions", "Troubleshooting")
TEST = Path(tempfile.mkdtemp(prefix='scriptlibrary-device-'))
definitions = {}
checks = 0

def check(ok, message):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(message)

for group in GROUPS:
    for path in sorted((BASE / group).glob("*.sh")):
        source = path.read_text(encoding='utf-8')
        data = {'name': path.stem, 'body': source.split('store_args "$@"\n',1)[1].rsplit('\nfinish',1)[0], 'mutating': source.split('MUTATING=',1)[1].splitlines()[0].strip() != 'false'}
        definitions[data["name"]] = data
        shell = TEST / (data["name"] + ".sh")
        shell.write_text("#!/bin/sh\n" + data["body"], encoding="utf-8", newline="\n")
        result = subprocess.run([str(BASH), "-n", str(shell)], capture_output=True, text=True)
        check(result.returncode == 0, path.name + " syntax: " + result.stderr)
        check(data["mutating"] is False, path.name + " must be read only")

check(len(definitions) == 15, "Exactly fifteen owned definitions must be present")

def write_fixture(root, path, value):
    dest = root / path.lstrip("/")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(value, encoding="utf-8")

COMMON = """
have() {
    case "$1" in
        journalctl|smartctl|nvme|lscpu|lspci|ethtool|systemd-detect-virt|lsof|testparm|exportfs|pvs|vgs|lvs|btrfs|zfs|zpool|rc-status|systemctl|dpkg-query|rpm|pacman|apk|getenforce|sestatus|aa-status|coredumpctl|needrestart|needs-restarting|zypper|ip|getfacl|lsblk)
            command -v "$1" >/dev/null 2>&1 && [ "$(type -t "$1")" = function ];;
        *) command -v "$1" >/dev/null 2>&1;;
    esac
}
"""

def case(name, script, files=None, args=None, mocks="", family="debian", init="unknown", expect=0):
    root = TEST / name
    report = root / "report"
    report.mkdir(parents=True, exist_ok=True)
    for rel, value in (files or {}).items():
        write_fixture(root, rel, value)
    (report / "findings.tsv").write_text("status\tcheck\tdetail\n", encoding="utf-8")
    (report / "facts.tsv").write_text("key\tvalue\n", encoding="utf-8")
    (report / ".arguments").write_text("".join(k + "\t" + str(v) + "\n" for k,v in (args or {}).items()), encoding="utf-8")
    harness = root / "run.sh"
    harness.write_text(
        ". " + shlex.quote((BASE / "lib" / "common.inc").as_posix()) + "\n" +
        "ROOT_FS=" + shlex.quote(root.as_posix()) + "\n" +
        "REPORT_DIR=" + shlex.quote(report.as_posix()) + "\n" +
        "OS_ID=fixture\nOS_VERSION=1\nOS_FAMILY=" + family + "\nINIT_SYSTEM=" + init + "\n" +
        COMMON + "\n" + mocks + "\n" + definitions[script]["body"],
        encoding="utf-8", newline="\n")
    result = subprocess.run([str(BASH), "--noprofile", "--norc", str(harness)],
                            capture_output=True, text=True, timeout=60)
    check(result.returncode == expect, name + ": exit " + str(result.returncode) + " stderr " + result.stderr)
    if expect == 0:
        check(not result.stderr.strip(), name + ": unexpected stderr " + result.stderr)
    else:
        check(result.stderr.strip().startswith('Error:'), name + ': expected a bounded validation error')
    all_text = "\n".join(p.read_text(encoding="utf-8") for p in report.glob("*") if p.is_file())
    return all_text, report

text, _ = case("battery-worn", "get-battery-health", {
    "sys/class/power_supply/BAT0/type":"Battery\n",
    "sys/class/power_supply/BAT0/energy_full":"400\n",
    "sys/class/power_supply/BAT0/energy_full_design":"1000\n",
    "sys/class/power_supply/BAT0/cycle_count":"800\n",
})
check("40.0" in text and "Warn\tBAT0.wear" in text, "Worn battery must warn")
text, _ = case("battery-good", "get-battery-health", {
    "sys/class/power_supply/BAT0/type":"Battery\n",
    "sys/class/power_supply/BAT0/charge_full":"900\n",
    "sys/class/power_supply/BAT0/charge_full_design":"1000\n",
})
check("90.0" in text and "Pass\tBAT0.wear" in text, "Charge-unit fallback should pass at 90%")
text, _ = case("battery-missing", "get-battery-health")
check("Unknown\tbattery_inventory" in text, "Missing battery is Unknown")
case("battery-invalid", "get-battery-health", args={"wear-warning-percent":"0"}, expect=2)

hardware_files = {
    "sys/block/sda/fixture":"visible\n",
    "sys/class/thermal/thermal_zone0/temp":"95000\n",
    "sys/class/thermal/thermal_zone0/type":"x86_pkg_temp\n",
}
text, _ = case("smart-failure", "check-hardware-health", hardware_files, mocks="""
smartctl() { printf '%s\\n' 'SMART overall-health self-assessment test result: FAILED!' 'Serial Number: DO_NOT_EXPORT_SERIAL'; return 8; }
""")
check("Fail\tsmart./dev/sda" in text, "SMART bit 3 should fail")
check("Warn\tthermal_zone0" in text, "High temperature must warn")
check("DO_NOT_EXPORT_SERIAL" not in text, "SMART serial must not be exported")
text, _ = case("smart-history", "check-hardware-health", hardware_files, mocks="""
smartctl() { printf '%s\\n' 'SMART overall-health self-assessment test result: PASSED'; return 64; }
""")
check("Warn\tsmart./dev/sda" in text, "SMART historical error bit should warn")
text, _ = case("smart-restricted", "check-hardware-health", hardware_files, mocks="""
smartctl() { return 2; }
""")
check("Unknown\tsmart./dev/sda" in text, "SMART access failure is Unknown")

text, _ = case("device-inventory", "get-device-information", {
    "proc/meminfo":"MemTotal: 4000 kB\nMemAvailable: 1000 kB\nSecret: DO_NOT_EXPORT_SECRET\n",
    "sys/class/dmi/id/product_name":"Fixture Laptop\n",
    "sys/class/dmi/id/product_serial":"DO_NOT_EXPORT_SERIAL\n",
    "proc/uptime":"12345.0 999.0\n",
}, mocks="""
lscpu() { printf '%s\\n' 'Architecture: x86_64' 'CPU(s): 8' 'Model name: Fixture CPU' 'Secret: DO_NOT_EXPORT_SECRET'; }
systemd-detect-virt() { printf '%s\\n' kvm; }
""")
check("CPU(s): 8" in text, "CPU count whitelist should match escaped parentheses")
check("Fixture Laptop" in text and "kvm" in text, "Model and virtualization inventory")
check("DO_NOT_EXPORT" not in text, "Hardware inventory must exclude serial and unrelated fields")

text, _ = case("driver-logs", "audit-drivers-and-firmware", {
    "proc/modules":"kvm 100 1 - Live 0x000000\n",
    "sys/class/net/eth0/fixture":"visible\n",
}, mocks="""
journalctl() { printf '%s\\n' 'firmware failed DO_NOT_EXPORT_LOG_SECRET' 'module verification failed SECRET'; }
ethtool() { printf '%s\\n' 'driver: fixture' 'firmware-version: 1' 'secret: DO_NOT_EXPORT_ETHTOOL'; }
""")
check("firmware_failure_candidates=1" in text, "Firmware error should be counted")
check("DO_NOT_EXPORT" not in text, "Driver audit must not export raw log text")

text, _ = case("virtualization", "test-virtualization-readiness", {
    "proc/cpuinfo":"flags : sse vmx aes\n",
    "proc/modules":"kvm_intel 1234 1 - Live 0x000000\n",
    "sys/kernel/iommu_groups/1/fixture":"visible\n",
}, mocks="""
uname() { printf '%s\\n' x86_64; }
""")
check("Pass\tcpu_virtualization" in text, "Visible VMX should pass CPU hint check")
check("visible_iommu_groups\t1" in text, "IOMMU group count should be recorded")

text, _ = case("capacity-threshold", "get-filesystem-capacity", {
    "proc/self/mounts":"//user:SECRET@host/share /share cifs rw,password=DO_NOT_EXPORT 0 0\n",
}, mocks="""
df() {
    printf '%s\\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on'
    if [ "$1" = -Pi ]; then printf '%s\\n' '/dev/sda 1000 200 800 20% /'
    else printf '%s\\n' '/dev/sda 1000 900 100 90% /'; fi
}
""")
check("Warn\tspace" in text and "Pass\tinodes" in text, "Independent inode and space thresholds")
check("target=/share type=cifs state=read-write" in text, "Mount type/state metadata")
check("SECRET" not in text and "DO_NOT_EXPORT" not in text, "Mount credentials must not be exported")
text, _ = case("capacity-unparseable", "get-filesystem-capacity", mocks="""
df() { printf '%s\\n' 'not capacity data'; }
""")
check("Unknown\tspace" in text, "Unparseable df must be Unknown")

text, _ = case("large-file-scan", "find-large-and-open-deleted-files",
    args={"path":"/", "minimum-mib":"1"}, mocks="""
find() {
    if [ "$1" = --help ]; then printf '%s\\n' maxdepth; return; fi
    printf '%s\\n' '4096 /fixture/large file.bin' '2048 /fixture/other.bin'
}
timeout() { shift; "$@"; }
lsof() { return 1; }
""")
check("4096 /fixture/large file.bin" in text, "Large-file metadata retained")
check("Unknown\topen_deleted_files" in text, "Empty lsof with ambiguous access must not pass")
text, _ = case("large-file-timeout", "find-large-and-open-deleted-files", args={"path":"/"}, mocks="""
find() { printf '%s\\n' maxdepth; }
timeout() { return 124; }
""")
check("Warn\tlarge_files" in text, "Truncated scan should report timeout")

text, _ = case("permission-scan", "audit-filesystem-permissions", args={"path":"/"}, mocks="""
find() {
    if [ "$1" = --help ]; then printf '%s\\n' maxdepth; return; fi
    printf '%s\\n' '-rwxrwxrwx 1 0 0 4096 Jan 1 00:00 /fixture/object'
}
timeout() { shift; "$@"; }
""")
check("Warn\tworld_writable" in text, "World writable findings should warn")
check("Warn\twritable_directories_without_sticky" in text, "Sticky-bit check should be present")
check("Warn\tsetuid_setgid_files" in text, "Special-bit audit should be present")

text, _ = case("share-security", "audit-network-shares", {
    "proc/self/mounts":"//user:DO_NOT_EXPORT@host/share /share cifs rw,password=SECRET 0 0\n",
}, mocks="""
testparm() {
    printf '%s\\n' '[global]' '    security = ADS' '    ldap admin dn = DO_NOT_EXPORT_DN' '[public]' '    guest ok = Yes' '    password = DO_NOT_EXPORT_PASSWORD' '    path = /'
}
exportfs() { printf '%s\\n' '/srv/share host.example(sync,rw,no_root_squash,insecure,sec=sys)'; }
""")
check("Warn\tsamba_guest_access" in text, "Guest shares should warn")
check("Warn\tnfs_root_squash" in text, "NFS no_root_squash should warn")
check("Warn\tnfs_source_ports" in text, "NFS insecure source ports should warn")
check("DO_NOT_EXPORT" not in text, "Share configuration secrets must be excluded")

text, _ = case("storage-layout", "audit-storage-layout", {
    "proc/mdstat":"Personalities : [raid1]\nmd0 : active raid1 sda1[0] sdb1[1]\n",
}, mocks="""
pvs() { [ "$1" = --readonly ] || return 99; printf '%s\\n' 'sda vg 100g 20g'; }
vgs() { [ "$1" = --readonly ] || return 99; printf '%s\\n' 'vg 100g 20g 1 2'; }
lvs() { [ "$1" = --readonly ] || return 99; printf '%s\\n' 'snap vg swi-a-s--- 10g origin 50'; }
""")
check("snap vg" in text and "md0 : active" in text, "LVM and MD inventory")
check("exit 99" not in text, "LVM reports must request read-only")

for family, mock in [
    ("debian", "dpkg-query() { printf '%s\\n' 'fixture 1.0'; }"),
    ("rhel", "rpm() { printf '%s\\n' 'fixture 1.0 x86_64'; }"),
    ("fedora", "rpm() { printf '%s\\n' 'fixture 1.0 x86_64'; }"),
    ("amazon", "rpm() { printf '%s\\n' 'fixture 1.0 x86_64'; }"),
    ("suse", "rpm() { printf '%s\\n' 'fixture 1.0 x86_64'; }"),
    ("arch", "pacman() { printf '%s\\n' 'fixture 1.0'; }"),
    ("alpine", "apk() { printf '%s\\n' 'fixture-1.0'; }"),
]:
    text, _ = case("bundle-" + family, "collect-support-bundle", {
        "proc/meminfo":"MemTotal: 4000 kB\nMemAvailable: 1000 kB\n",
    }, args={"include-network":"no"}, mocks=mock, family=family)
    check("fixture" in text and "installed_package_count\t1" in text, "Package adapter " + family)

text, _ = case("performance", "get-performance-snapshot", {
    "proc/stat":"cpu 1 2 3 4 5 6 7 8\n",
    "proc/meminfo":"MemTotal: 1000 kB\nMemAvailable: 100 kB\n",
    "proc/loadavg":"1.0 2.0 3.0 1/9 9999\n",
    "proc/pressure/cpu":"some avg10=1.00 avg60=2.00 avg300=3.00 total=100\n",
    "proc/diskstats":"8 0 sda 1 2 3 4 5 6 7 8 9 10 11\n",
}, args={"samples":"1"}, mocks="""
ps() { printf '%s\\n' 'PID PPID COMMAND %CPU %MEM' '1 0 fixture 2.0 1.0'; }
""")
check("sample=1" in text and "pressure_cpu" in text, "Performance sample and PSI")
check("sectors_read=3" in text, "Disk counters should preserve field mapping")
check("9999" not in text, "Loadavg task/PID field should be excluded")

text, _ = case("kernel-errors", "audit-boot-and-kernel-errors", mocks="""
journalctl() {
    case "$1" in --list-boots) printf '%s\\n' '0 fixture today today';;
        *) printf '%s\\n' 'Out of memory: killed process DO_NOT_EXPORT_LOG' 'Buffer I/O error on device SECRET' 'segfault DO_NOT_EXPORT_ARG';;
    esac
}
""")
check("oom_candidates=1" in text and "io_filesystem_candidates=1" in text, "Kernel error classes should be counted")
check("Warn\tkernel_error_candidates" in text, "Kernel error candidates should warn")
check("DO_NOT_EXPORT" not in text and "SECRET" not in text, "No raw kernel text should escape")
text, _ = case("kernel-empty", "audit-boot-and-kernel-errors", mocks="journalctl() { return 0; }")
check("Unknown\tkernel_messages" in text, "Empty journal must be Unknown")

text, _ = case("policy-denials", "audit-security-policy-denials", mocks="""
getenforce() { printf '%s\\n' Enforcing; }
journalctl() { printf '%s\\n' 'avc: denied password=DO_NOT_EXPORT' 'apparmor="DENIED" command=DO_NOT_EXPORT'; }
""")
check("selinux_denial_candidates=1" in text and "apparmor_denial_candidates=1" in text, "Both policy families should be counted")
check("Warn\tpolicy_denials" in text, "Denial candidates should warn")
check("DO_NOT_EXPORT" not in text, "No raw denial text should escape")

text, _ = case("restart-list", "check-restart-requirements", mocks="""
needrestart() {
    [ "$1 $2 $3" = '-b -r l' ] || return 99
    printf '%s\\n' 'NEEDRESTART-KSTA: 3' 'NEEDRESTART-SVC: ssh.service' 'UNRELATED: DO_NOT_EXPORT'
}
""")
check("Warn\tservice_restart_candidates" in text and "Warn\tkernel_restart_candidate" in text, "Restart candidates should warn")
check("DO_NOT_EXPORT" not in text, "Only whitelisted batch keys should escape")
text, _ = case("restart-rpm", "check-restart-requirements", mocks="""
needs-restarting() { [ "$1" = -r ] || return 99; return 1; }
""", family="rhel")
check("Warn\trpm_reboot_check" in text, "RPM exit 1 indicates reboot")
text, _ = case("restart-unknown", "check-restart-requirements")
check("Unknown\trestart_requirement" in text, "Missing restart tooling must be Unknown")

report = {"checks":checks, "definition_count":len(definitions),
          "runtime":str(BASH) + ", mocked Linux commands and fixture procfs/sysfs",
          "evidence":str(TEST),
          "limitations":"No Linux kernel, real package database, disks, VMs, network shares, SELinux, AppArmor, or reboot was tested."}
(TEST / "device-storage-troubleshooting-test-results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report))
