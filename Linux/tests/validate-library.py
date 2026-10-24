#!/usr/bin/env python3
"""Validate source and mocked controls. Does not configure the host or require root."""
import argparse
import json
import os
import pathlib
import subprocess
import tempfile


def shell_path(path):
    value = str(pathlib.Path(path).resolve()).replace('\\', '/')
    if os.name == 'nt' and len(value) > 2 and value[1] == ':':
        value = '/' + value[0].lower() + value[2:]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument('--shell', default='/bin/sh', help='POSIX shell executable; Git Bash can run source/control mocks on Windows')
    args = parser.parse_args()
    root = args.root.resolve()
    catalog = json.loads((root / 'catalog.json').read_text(encoding='utf-8'))
    checks = 0
    failures = []

    def check(condition, label, detail=''):
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(label + (': ' + detail[:600] if detail else ''))

    def run(argv, env=None):
        return subprocess.run([args.shell, *argv], capture_output=True, text=True, timeout=20, env=env)

    check(len(catalog) == 45, '45 operational tools')
    scripts = sorted(root.glob('*/*.sh'))
    check(len(scripts) == 45, '45 category entry points')
    check(len({d['name'] for d in catalog}) == 45, 'unique names')
    lib = shell_path(root / 'lib/common.inc')
    syntax = run(['-n', lib])
    check(syntax.returncode == 0, 'common syntax', syntax.stderr)
    with tempfile.TemporaryDirectory(prefix='scriptlibrary-') as temp:
        temp = pathlib.Path(temp)
        mock = temp / 'mock'
        mock.mkdir()
        (mock / 'uname').write_text('#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; *) echo fixture;; esac\n', encoding='utf-8', newline='\n')
        (mock / 'uname').chmod(0o755)
        env = os.environ.copy()
        env['PATH'] = shell_path(mock) + os.pathsep + env.get('PATH', '')
        # Git Bash imports PATH from a semicolon separated Windows environment.
        for data in catalog:
            script = root / data['category'] / (data['name'] + '.sh')
            source = script.read_text(encoding='utf-8')
            label = data['name']
            check(source.startswith('#!/bin/sh\n# What it does\n'), label + ' header')
            check('# Available flags\n' in source and '# How it works\n' in source, label + ' sections')
            check('\r' not in source, label + ' LF endings')
            result = run(['-n', shell_path(script)])
            check(result.returncode == 0, label + ' syntax', result.stderr)
            result = run([shell_path(script), '--help'])
            check(result.returncode == 0 and label in result.stdout, label + ' help', result.stderr)
            result = run(['-c', 'PATH="$1:$PATH"; export PATH; shift; exec sh "$@"', 'validate', shell_path(mock), shell_path(script), '--not-a-real-option'])
            check(result.returncode == 2 and 'Unknown flag' in result.stderr, label + ' rejects flags before reports', result.stderr)
            if not data['mutating']:
                result = run(['-c', 'PATH="$1:$PATH"; export PATH; shift; exec sh "$@"', 'validate', shell_path(mock), shell_path(script), '--apply'])
                check(result.returncode == 2 and 'audit' in result.stderr, label + ' rejects apply', result.stderr)
            if data['options']:
                key = data['options'].split()[0]
                result = run(['-c', 'PATH="$1:$PATH"; export PATH; shift; exec sh "$@"', 'validate', shell_path(mock), shell_path(script), '--' + key])
                check(result.returncode == 2 and 'needs a value' in result.stderr, label + ' missing flag value', result.stderr)

        profiles = {'debian': 'debian', 'ubuntu': 'debian', 'linuxmint': 'debian', 'pop': 'debian', 'rhel': 'rhel', 'rocky': 'rhel', 'almalinux': 'rhel', 'ol': 'rhel', 'fedora': 'fedora', 'amzn': 'amazon', 'opensuse-tumbleweed': 'suse', 'sles': 'suse', 'arch': 'arch', 'manjaro': 'arch', 'alpine': 'alpine', 'unknown': 'unknown'}
        for distro, family in profiles.items():
            fixture = temp / (distro + '.os-release')
            fixture.write_text('ID="' + distro + '"\nVERSION_ID="2025"\n', encoding='utf-8')
            result = run(['-c', '. "$1"; detect_os "$2"; printf "%s:%s:%s" "$OS_ID" "$OS_VERSION" "$OS_FAMILY"', 'validate', lib, shell_path(fixture)])
            check(result.stdout == distro + ':2025:' + family, distro + ' detection', result.stdout + result.stderr)
        marker = temp / 'executed'
        fixture = temp / 'evil.os-release'
        fixture.write_text('ID="debian"\nVERSION_ID="$(touch ' + shell_path(marker) + ')"\n', encoding='utf-8')
        result = run(['-c', '. "$1"; detect_os "$2"; printf "%s" "$OS_VERSION"', 'validate', lib, shell_path(fixture)])
        check(not marker.exists() and '$(touch' in result.stdout, 'os-release values are never executed')
        report = temp / 'report'
        report.mkdir()
        harness = '''
. "$1"
REPORT_DIR=$2
printf 'status\\tcheck\\tdetail\\n' > "$REPORT_DIR/findings.tsv"
printf 'key\\tvalue\\n' > "$REPORT_DIR/facts.tsv"
fake_probe() { printf 'https://user:TOPSECRET@example.test/ TOKEN=TOPSECRET\\n'; printf 'PRIVATE_ERROR\\n' >&2; return 7; }
capture failing fake_probe
printf '%s' "$LAST_CAPTURE_RC" > "$REPORT_DIR/exit-code"
many_lines() { awk 'BEGIN {for(i=1;i<=600;i++) print i}'; }
capture bounded many_lines
capture missing surely_missing_scriptlibrary_tool
APPLY=0
change plan touch "$REPORT_DIR/should-not-exist"
APPLY=1; DEFER_RESTARTS=1; INIT_SYSTEM=systemd
restart_service example
'''
        result = run(['-c', harness, 'validate', lib, shell_path(report)])
        check(result.returncode == 0, 'helper fixture runs', result.stderr)
        evidence = (report / 'failing.txt').read_text()
        check('TOPSECRET' not in evidence and '[redacted]' in evidence, 'credential redaction')
        check('PRIVATE_ERROR' not in evidence, 'stderr excluded')
        check((report / 'exit-code').read_text() == '7', 'capture preserves probe exit')
        check(len((report / 'bounded.txt').read_text().splitlines()) == 501, 'output limited with truncation marker')
        findings = (report / 'findings.tsv').read_text()
        check('Unknown\tfailing' in findings and 'Unknown\tmissing' in findings, 'failed/missing checks unknown')
        check(not (report / 'should-not-exist').exists(), 'plan executes no changes')
        check('restart-deferred' in findings, 'deferred restart never runs')
        check(not list(report.glob('.status.*')), 'temporary status cleaned')

    result = {'checks': checks, 'failures': failures, 'shell': args.shell, 'scope': 'source syntax and isolated mocked controls; no live Linux configuration or distro integration'}
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if failures else 0)


if __name__ == '__main__':
    main()
