"""Validate actual Linux software, identity, and workstation scripts with private files and command mocks."""
import argparse
import json
import shlex
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
parser.add_argument('--shell', default='/bin/sh')
parser.add_argument('--work-dir', type=Path, help='Optional parent for retained private fixture evidence.')
args = parser.parse_args()
ROOT = args.root.resolve()
BASE = Path(tempfile.mkdtemp(prefix='sl-software-', dir=args.work_dir))
results = []


def check(value, label):
    results.append((label, bool(value)))
    if not value:
        raise AssertionError(label)


def shell_path(path):
    value = str(path.resolve()).replace('\\', '/')
    return '/' + value[0].lower() + value[2:] if len(value) > 2 and value[1] == ':' else value


definitions = {}
for category in ('Software', 'Users-and-Groups', 'Workstation-Setup'):
    for path in sorted((ROOT / category).glob('*.sh')):
        source = path.read_text(encoding='utf-8')
        body = source.split('store_args "$@"\n', 1)[1].rsplit('\nfinish', 1)[0]
        definitions[path.stem] = body
        script = BASE / path.name
        script.write_text(body, encoding='utf-8', newline='\n')
        result = subprocess.run([args.shell, '-n', shell_path(script)], capture_output=True, text=True)
        check(result.returncode == 0, path.name + ' POSIX syntax')
        check('eval ' not in body, path.name + ' has no eval')
check(len(definitions) == 15, '15 actual installed category scripts')


def scenario(name, values=None, *, apply=False, defer=True, family='debian', mocks=None, extra='', replacements=None, expect=0):
    folder = BASE / ('case-' + str(len(results)))
    folder.mkdir()
    mock_dir = folder / 'mock'
    mock_dir.mkdir()
    fs = folder / 'fs'
    for relative in ('home', 'etc', 'etc/systemd/timesyncd.conf.d', 'var'):
        (fs / relative).mkdir(parents=True, exist_ok=True)
    (fs / 'etc/passwd').write_text('', encoding='utf-8')
    (fs / 'etc/group').write_text('technicians:x:1234:\n', encoding='utf-8')
    mocks = dict(mocks or {})
    mocks['id'] = 'case "$1" in -u) echo 0;; *) echo fixture;; esac\n'
    for command, body in mocks.items():
        destination = mock_dir / command
        destination.write_text('#!/bin/sh\n' + body, encoding='utf-8', newline='\n')
        destination.chmod(0o755)
    options = ''
    for key, value in (values or {}).items():
        options += ' ' + shlex.quote(key) + ") printf '%s\\n' " + shlex.quote(str(value)) + ';;\n'
    body = definitions[name]
    # Only the fixture's account body is redirected; production source remains unchanged.
    if name == 'provision-local-user':
        body = body.replace('home="/home/$newuser"', 'home="$FIXTURE_FS/home/$newuser"')
        body = body.replace('[ -d /home ] && [ ! -L /home ]', '[ -d "$FIXTURE_FS/home" ] && [ ! -L "$FIXTURE_FS/home" ]')
        body = body.replace(' /etc/group', ' "$FIXTURE_FS/etc/group"').replace(' /etc/passwd', ' "$FIXTURE_FS/etc/passwd"')
    if name == 'configure-time-synchronization':
        body = body.replace('/etc/chrony/chrony.conf /etc/chrony.conf', '"$FIXTURE_FS/etc/chrony/chrony.conf" "$FIXTURE_FS/etc/chrony.conf"')
        body = body.replace('/etc/systemd', '"$FIXTURE_FS/etc/systemd"')
    if name == 'plan-system-updates':
        for path in ('/var/lib/apt/lists', '/var/cache/dnf', '/run/reboot-required'):
            body = body.replace(path, '"$FIXTURE_FS' + path + '"')
    for old, new in (replacements or {}).items():
        body = body.replace(old, new)
    script = folder / 'harness.sh'
    common = folder / 'common.fixture.inc'
    common.write_text((ROOT / 'lib/common.inc').read_text(encoding='utf-8').replace('/run/ostree-booted', '"$FIXTURE_FS/run/ostree-booted"'), encoding='utf-8', newline='\n')
    harness = (
        '. ' + shlex.quote(shell_path(common)) + '\n'
        'REPORT_DIR=' + shlex.quote(shell_path(folder)) + '\n'
        'FIXTURE_FS=' + shlex.quote(shell_path(fs)) + '\n'
        'HOME="$FIXTURE_FS/home"; export HOME\n'
        'PATH=' + shlex.quote(shell_path(mock_dir)) + ':/usr/bin:/bin; export PATH\n'
        'LOG="$REPORT_DIR/actions"; export LOG\n'
        'printf "status\\tcheck\\tdetail\\n" > "$REPORT_DIR/findings.tsv"\n'
        'printf "key\\tvalue\\n" > "$REPORT_DIR/facts.tsv"\n'
        ': > "$REPORT_DIR/.arguments"\n'
        'ROOT_FS="$FIXTURE_FS"\n'
        'OS_ID=fixture; OS_VERSION=13; OS_FAMILY=' + shlex.quote(family) + '; INIT_SYSTEM=systemd\n'
        'APPLY=' + str(int(apply)) + '; DEFER_RESTARTS=' + str(int(defer)) + '\n'
        'arg() { case "$1" in\n' + options + ' *) printf "%s\\n" "${2-}";; esac; }\n'
        'have() { case "$1" in ' + '|'.join(mocks) + ') command -v "$1" >/dev/null 2>&1;; *) [ "$(command -v "$1")" = "$1" ];; esac; }\n'
        + extra + '\n' + body + '\nexit 0\n'
    )
    script.write_text(harness, encoding='utf-8', newline='\n')
    result = subprocess.run([args.shell, shell_path(script)], capture_output=True, text=True, timeout=20)
    (folder / 'result.json').write_text(json.dumps({'code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}), encoding='utf-8')
    check(result.returncode == expect, name + ': expected exit ' + str(expect) + ', got ' + str(result.returncode) + ' ' + result.stderr)
    log = (folder / 'actions').read_text() if (folder / 'actions').exists() else ''
    findings = (folder / 'findings.tsv').read_text()
    return result, log, findings, folder


user_mocks = {
    'getent': 'exit 2\n',
    'useradd': 'printf "useradd %s\\n" "$*" >> "$LOG"; exit 9\n',
    'passwd': 'printf "FORBIDDEN-passwd %s\\n" "$*" >> "$LOG"\n',
}
result, log, findings, folder = scenario('provision-local-user', {'user': 'fixturetest'}, apply=True, mocks=user_mocks)
check('useradd ' in log and 'FORBIDDEN-passwd' not in log, 'failed user creation never attempts passwd')
check('Fail\tcreate-local-user' in findings and not (folder / 'fs/home/fixturetest').exists(), 'failed account creation leaves no home or SSH key')
result, log, findings, folder = scenario('provision-local-user', {'user': 'fixturetest'}, mocks=user_mocks)
check(not log and 'Planned action' in findings, 'account plan creates no account or password change')
result, log, findings, folder = scenario('provision-local-user', {'user': '-option'}, mocks=user_mocks, expect=2)
check(not log, 'invalid account name rejected before commands')

baseline_mocks = {'hostnamectl': 'printf "hostnamectl %s\\n" "$*" >> "$LOG"\n', 'systemctl': 'exit 0\n', 'timedatectl': 'exit 0\n', 'localectl': 'exit 0\n'}
result, log, findings, folder = scenario('configure-workstation-baseline', {'hostname': 'technician01'}, mocks=baseline_mocks)
check(not log, 'hostname plan changes nothing')
result, log, findings, folder = scenario('configure-workstation-baseline', {'hostname': 'technician01'}, apply=True, mocks=baseline_mocks)
check('hostnamectl set-hostname technician01' in log, 'explicit hostname apply uses detected adapter')
result, log, findings, folder = scenario('configure-workstation-baseline', {'hostname': '-invalid'}, apply=True, mocks=baseline_mocks, expect=2)
check(not log, 'invalid hostname rejected before action')

ufw = 'case "$1" in status) echo "Status: active";; *) printf "ufw %s\\n" "$*" >> "$LOG";; esac\n'
result, log, findings, folder = scenario('configure-endpoint-firewall', {'port': '443'}, mocks={'ufw': ufw})
check(not log, 'UFW plan changes no rules')
result, log, findings, folder = scenario('configure-endpoint-firewall', {'port': '443'}, apply=True, mocks={'ufw': ufw})
check('ufw allow 443/tcp' in log and not any(word in log for word in ('flush', 'reload', 'reset', 'disable')), 'UFW apply is additive and retains management policy')
firewalld = '''case "$*" in
 --state) exit 0;;
 --get-zones) echo 'public internal';;
 *--query-port=*) exit 0;;
 *) printf 'firewall-cmd %s\\n' "$*" >> "$LOG";;
esac
'''
result, log, findings, folder = scenario('configure-endpoint-firewall', {'port': '443', 'zone': 'public'}, mocks={'firewall-cmd': firewalld})
check(not log and 'Unknown' not in findings, 'firewalld plan writes neither runtime nor permanent rules')
result, log, findings, folder = scenario('configure-endpoint-firewall', {'port': '443', 'zone': 'public'}, apply=True, mocks={'firewall-cmd': firewalld})
check('--zone=public --add-port=443/tcp' in log and '--permanent --zone=public --add-port=443/tcp' in log, 'firewalld applies selected runtime and permanent allowances')
check(not any(word in log for word in ('flush', 'reload', 'reset', 'disable')), 'firewalld never replaces or reloads policy')
failed_firewalld = firewalld.replace("*) printf", "*--add-port=*) printf 'failed-runtime\\n' >> \"$LOG\"; exit 9;;\n *) printf")
result, log, findings, folder = scenario('configure-endpoint-firewall', {'port': '443', 'zone': 'public'}, apply=True, mocks={'firewall-cmd': failed_firewalld}, expect=2)
check('--permanent' not in log, 'failed runtime allow blocks permanent allow')

result, log, findings, folder = scenario('plan-system-updates', family='fedora', mocks={'dnf': 'echo "curl.x86_64 2.0 updates"; exit 100\n', 'df': 'echo fixture-space\n'})
check('Unknown\tcached-update-list' not in findings and 'updates' in (folder / 'cached-update-list.txt').read_text(), 'DNF update-available exit 100 is successful evidence')
result, log, findings, folder = scenario('plan-system-updates', family='fedora', mocks={'dnf': 'exit 1\n', 'df': 'echo fixture-space\n'})
check('Unknown\tcached-update-list' in findings, 'DNF failure exit 1 stays Unknown')

package_extra = 'printf "debian\\tcurl\\n" > "$REPORT_DIR/manifest.tsv"\narg() { case "$1" in manifest) printf "%s\\n" "$REPORT_DIR/manifest.tsv";; *) printf "%s\\n" "${2-}";; esac; }\n'
package_mock = {'apt-get': 'printf "FORBIDDEN-install %s\\n" "$*" >> "$LOG"\n'}
result, log, findings, folder = scenario('install-approved-software', apply=True, mocks=package_mock, extra=package_extra)
check(not log and 'restart-deferred' in findings, 'package --defer-restarts defers entire installation')
result, log, findings, folder = scenario('install-approved-software', mocks=package_mock, extra=package_extra)
check(not log and (folder / 'approved-packages.txt').read_text().strip() == 'curl', 'approved software plan validates manifest without installation')
result, log, findings, folder = scenario('initialize-technician-workstation', mocks=package_mock)
check('debian\tdnsutils' in (folder / 'technician-packages.tsv').read_text() and not log, 'Debian technician profile maps DNS tools without installation')
result, log, findings, folder = scenario('initialize-technician-workstation', family='alpine', mocks={'apk': 'printf "FORBIDDEN-apk %s\\n" "$*" >> "$LOG"\n'})
check('alpine\tbind-tools' in (folder / 'technician-packages.tsv').read_text() and not log, 'Alpine technician profile uses its package names')

time_mocks = {'systemctl': '''case "$*" in
 'is-active --quiet chronyd'|'is-active --quiet chrony') [ "$TIME_MODE" = aliases ];;
 'is-active --quiet systemd-timesyncd') [ "$TIME_MODE" = timesyncd ];;
 'is-active --quiet ntpd') [ "$TIME_MODE" = ntpd ];;
 is-active*) exit 3;;
 *) printf 'FORBIDDEN-systemctl %s\\n' "$*" >> "$LOG";;
esac
'''}
time_extra = '''TIME_MODE=timesyncd; export TIME_MODE
mkdir() { printf 'mkdir %s\\n' "$*" >> "$LOG"; }
write_config_file() { printf 'write_config_file %s\\n' "$*" >> "$LOG"; return 9; }
restart_service() { printf 'FORBIDDEN-restart %s\\n' "$*" >> "$LOG"; }
'''
result, log, findings, folder = scenario('configure-time-synchronization', {'servers': 'ntp.example.invalid'}, apply=True, mocks=time_mocks, extra=time_extra)
check('write_config_file ' in log and 'FORBIDDEN-restart' not in log, 'time configuration write failure blocks restart')
result, log, findings, folder = scenario('configure-time-synchronization', {'servers': 'ntp.example.invalid'}, mocks=time_mocks, extra='TIME_MODE=aliases; export TIME_MODE\n')
check('conflicting daemons' not in findings, 'chrony aliases counted once rather than as competing daemons')
result, log, findings, folder = scenario('configure-time-synchronization', {'servers': 'ntp.example.invalid'}, apply=True, mocks=time_mocks, extra='TIME_MODE=ntpd; export TIME_MODE\n')
check('Unknown\tntpd' in findings and not log, 'unsupported ntpd variants never rewrite configuration or restart')

summary = {'checks': len(results), 'failed': 0, 'definition_count': len(definitions), 'evidence': str(BASE), 'scope': 'Actual materialized bodies, POSIX syntax, private filesystem fixtures, and command mocks. No host Linux or Windows configuration changed.'}
(BASE / 'test-results.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
print(json.dumps(summary, indent=2))
