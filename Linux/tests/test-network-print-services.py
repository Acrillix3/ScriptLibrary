import json
import os
import argparse
from pathlib import Path
import shlex
import subprocess
import tempfile
from contextlib import nullcontext

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description="Run syntax and isolated mocked network, print, and service controls; never configures the host.")
parser.add_argument("--root", type=Path, default=HERE.parent, help="Complete Linux library directory.")
parser.add_argument("--shell", default="/bin/sh", help="POSIX shell executable.")
parser.add_argument("--work-dir", type=Path, help="Optional writable directory for retained test evidence.")
args = parser.parse_args()
ROOT = args.root.resolve()
SHELL = args.shell
results = []

def check(value, label):
    results.append((label, bool(value)))

def shell_path(path):
    value = str(path.resolve()).replace("\\", "/")
    return "/" + value[0].lower() + value[2:] if len(value) > 2 and value[1] == ":" else value

definitions = {}
for category in ("Network-and-DNS", "Printing", "Services"):
    for path in (ROOT / category).glob("*.sh"):
        text = path.read_text(encoding="utf-8")
        body = text.split('store_args "$@"\n', 1)[1].rsplit("\nfinish", 1)[0]
        definitions[path.stem] = {"body": body}
check(len(definitions) == 15, "15 installed category scripts")

with nullcontext(tempfile.mkdtemp(prefix="sl-network-", dir=args.work_dir)) as temporary:
    base = Path(temporary)
    common = shell_path(ROOT / "lib" / "common.inc")
    for name, data in definitions.items():
        script = base / (name + ".sh")
        script.write_text(data["body"], encoding="utf-8", newline="\n")
        result = subprocess.run([SHELL, "-n", shell_path(script)], capture_output=True, text=True)
        check(result.returncode == 0, name + " POSIX syntax")
        check("eval " not in data["body"], name + " no eval")

    def scenario(name, values=None, apply=False, defer=True, init="systemd", mocks=None, extra=""):
        folder = base / ("case-" + str(len(results)))
        folder.mkdir()
        mock = folder / "mock"
        mock.mkdir()
        log = folder / "actions"
        mocks = mocks or {}
        mocks["id"] = 'case "$1" in -u) echo 0;; -un) echo fixture;; esac\n'
        for command, body in mocks.items():
            (mock / command).write_text('#!/bin/sh\n' + body, encoding="utf-8", newline="\n")
            (mock / command).chmod(0o755)
        options = ""
        for key, value in (values or {}).items():
            options += "    " + shlex.quote(key) + ") printf '%s\\n' " + shlex.quote(str(value)) + ";;\n"
        allowed = "|".join(mocks)
        harness = (
            '. ' + shlex.quote(common) + '\n'
            'REPORT_DIR=' + shlex.quote(shell_path(folder)) + '\n'
            'PATH=' + shlex.quote(shell_path(mock)) + ':/usr/bin:/bin; export PATH\n'
            'LOG=' + shlex.quote(shell_path(log)) + '; export LOG\n'
            'printf "status\\tcheck\\tdetail\\n" > "$REPORT_DIR/findings.tsv"\n'
            'printf "key\\tvalue\\n" > "$REPORT_DIR/facts.tsv"\n'
            'APPLY=' + str(int(apply)) + '; DEFER_RESTARTS=' + str(int(defer)) + '\n'
            'INIT_SYSTEM=' + shlex.quote(init) + '\n'
            'arg() { case "$1" in\n' + options + '    *) printf "%s\\n" "$2";; esac; }\n'
            'have() { case "$1" in ' + allowed + ') command -v "$1" >/dev/null 2>&1;; *) [ "$(command -v "$1")" = "$1" ];; esac; }\n'
            + extra + '\n'
            + definitions[name]["body"] + '\n'
            + 'exit 0\n'
        )
        script = folder / "harness.sh"
        script.write_text(harness, encoding="utf-8", newline="\n")
        result = subprocess.run([SHELL, shell_path(script)], capture_output=True, text=True, timeout=15)
        (folder / 'result.json').write_text(json.dumps({'code': result.returncode, 'out': result.stdout, 'err': result.stderr}), encoding='utf-8')
        if not (folder / "findings.tsv").exists():
            raise RuntimeError(result.stdout + result.stderr)
        return result, log.read_text() if log.exists() else "", (folder / "findings.tsv").read_text(), folder

    systemctl = '''case "$*" in
*--property=LoadState*) echo loaded;;
*--property=Id*) echo chrony.service;;
*is-active*) case "$*" in *chronyd.service*|*chrony.service*) exit 0;; *) exit 3;; esac;;
start*|stop*|restart*|enable*|disable*) printf '%s\\n' "systemctl $*" >> "$LOG";;
*) echo 'Id=fixture.service';;
esac
'''
    args = {"service": "fixture", "enabled": "yes", "state": "start"}
    result, log, findings, folder = scenario("configure-service-state", args, mocks={"systemctl": systemctl})
    check(result.returncode == 0 and not log, "service plan executes no action")
    result, log, findings, folder = scenario("configure-service-state", args, apply=True, mocks={"systemctl": systemctl})
    check(result.returncode == 0 and "systemctl enable fixture.service" in log and "systemctl start fixture.service" in log, "explicit service start and enable")
    result, log, findings, folder = scenario("configure-service-state", {"service": "fixture", "state": "restart"}, apply=True, mocks={"systemctl": systemctl})
    check(result.returncode == 0 and "restart fixture" not in log and "restart-deferred" in findings, "service restart separately deferred")
    result, log, findings, folder = scenario("configure-service-state", {"service": "fixture", "state": "restart"}, apply=True, defer=False, mocks={"systemctl": systemctl})
    check(result.returncode == 0 and "restart fixture" not in log and "confirmation-required" in findings, "noninteractive service restart deferred")

    nmcli = '''case "$*" in
*'GENERAL.CON-UUID device show'*) echo aaaa-bbbb;;
*'connection.type connection show'*) echo 802-3-ethernet;;
*'connection.master connection show'*|*'802-1x.eap connection show'*) :;;
*'connection.uuid connection show id'*) exit 10;;
'connection clone'*|'connection modify'*|*'connection up'*) printf '%s\\n' "nmcli $*" >> "$LOG";;
*) echo fixture;;
esac
'''
    network_args = {"interface": "eth0", "connection": "aaaa-bbbb", "profile": "new-static", "address": "192.0.2.10/24", "gateway": "192.0.2.1", "dns": "192.0.2.53,192.0.2.54"}
    result, log, findings, folder = scenario("configure-static-network", network_args, mocks={"nmcli": nmcli})
    check(result.returncode == 0 and not log, "network plan executes no change")
    result, log, findings, folder = scenario("configure-static-network", network_args, apply=True, mocks={"nmcli": nmcli})
    check(result.returncode == 0 and "connection clone uuid aaaa-bbbb new-static" in log and "connection modify id new-static connection.autoconnect no" in log and "connection up" not in log, "network clone preserves original and defers activation")
    failed_nmcli = nmcli.replace("'connection clone'*|'connection modify'*|*'connection up'*)", "'connection modify'*) printf '%s\\n' failed-modify >> \"$LOG\"; exit 8;;\n'connection clone'*|*'connection up'*)")
    result, log, findings, folder = scenario("configure-static-network", network_args, apply=True, mocks={"nmcli": failed_nmcli})
    check("failed-modify" in log and "connection up" not in log and "Fail\tprofile-staging" in findings, "failed network modification never activates")
    bad_args = dict(network_args, dns="192.0.2.53,,192.0.2.54")
    result, log, findings, folder = scenario("configure-static-network", bad_args, apply=True, mocks={"nmcli": nmcli})
    check(result.returncode == 2 and not log, "empty DNS list element rejected")

    lpstat = '''case "$*" in -r) echo running;; '-p fixture') echo 'printer fixture disabled';; '-p new-printer') exit 1;; *) echo fixture;; esac\n'''
    printer_command = 'printf "%s\\n" "$0 $*" >> "$LOG"\n'
    result, log, findings, folder = scenario("configure-network-printer", {"queue": "new-printer", "uri": "ipp://printer.example/ipp/print"}, mocks={"lpstat": lpstat, "lpadmin": printer_command})
    check(result.returncode == 0 and not log, "printer creation plan performs no change")
    result, log, findings, folder = scenario("configure-network-printer", {"queue": "new-printer", "uri": "ipp://printer.example/ipp/print"}, apply=True, mocks={"lpstat": lpstat, "lpadmin": printer_command})
    check(result.returncode == 0 and "-p new-printer -E -v ipp://printer.example/ipp/print -m everywhere -o printer-is-shared=false" in log, "new queue created unshared")
    result, log, findings, folder = scenario("configure-network-printer", {"queue": "fixture", "uri": "ipp://printer.example/ipp/print"}, apply=True, mocks={"lpstat": lpstat, "lpadmin": printer_command})
    check(result.returncode == 2 and not log, "existing queue never overwritten")
    result, log, findings, folder = scenario("configure-network-printer", {"queue": "new-printer", "uri": "ipp://name:SECRET@printer.example/ipp/print"}, apply=True, mocks={"lpstat": lpstat, "lpadmin": printer_command})
    check(result.returncode == 2 and not log and "SECRET" not in result.stdout, "printer credential URI rejected without disclosure")
    result, log, findings, folder = scenario("repair-print-queue", {"queue": "fixture", "action": "release"}, apply=True, mocks={"lpstat": lpstat, "cupsenable": printer_command})
    check(result.returncode == 0 and not log and "restart-deferred" in findings, "print release respects separate deferral")
    result, log, findings, folder = scenario("repair-print-queue", {"queue": "fixture", "action": "enable"}, apply=True, mocks={"lpstat": lpstat, "cupsenable": printer_command})
    check(result.returncode == 0 and "cupsenable fixture" in log and "-c" not in log, "queue enable never cancels jobs")
    result, log, findings, folder = scenario("test-printer-connectivity", {"target": "printer.example", "uri": "ipp://other.example/ipp/print"})
    check(result.returncode == 2, "IPP URI must match selected target")

    result, log, findings, folder = scenario("audit-firewall-rules", mocks={"nft": "echo harmless; exit 7\n"})
    check("exit 7" in findings and "Unknown\tnftables" in findings, "nft pipeline preserves provider failure")
    result, log, findings, folder = scenario("test-remote-access", mocks={"sshd": "exit 7\n"})
    check("exit 7" in findings and "Unknown\tsshd-effective" in findings, "sshd projection preserves provider failure")
    result, log, findings, folder = scenario("audit-time-synchronization", mocks={"systemctl": systemctl})
    check(result.returncode == 0 and "competing-daemons" not in findings, "time service aliases are deduplicated")
    result, log, findings, folder = scenario("export-print-configuration", mocks={"lpstat": "case \"$1\" in -v) echo 'device for fixture: smb://domain/user:SECRET@server/share?token=SECRET';; *) echo fixture;; esac\n"})
    exported = "\n".join(p.read_text() for p in folder.glob("*.txt"))
    check("SECRET" not in exported and "[redacted]@server" in exported, "printer metadata redacts nested URI userinfo and query")

for label, passed in results:
    if not passed:
        print("FAIL:", label)
print(json.dumps({"checks": len(results), "failed": sum(not p for _, p in results), "evidence": str(base), "scope": "POSIX syntax and isolated command mocks; no live Linux execution"}, indent=2))
raise SystemExit(0 if all(p for _, p in results) else 1)
