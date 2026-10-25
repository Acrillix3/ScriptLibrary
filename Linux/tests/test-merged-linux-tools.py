#!/usr/bin/env python3
"""Exercise the four merged CUPS/SSH entrypoints with private libraries, files and provider mocks."""
import argparse
import json
import pathlib
import shlex
import subprocess
import tempfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1])
parser.add_argument('--shell',default='/bin/sh')
parser.add_argument('--work-dir',type=pathlib.Path)
args=parser.parse_args()
ROOT=args.root.resolve()
BASE=pathlib.Path(tempfile.mkdtemp(prefix='sl-merged-linux-',dir=args.work_dir))
checks=[]

def shell_path(path):
    value=str(pathlib.Path(path).resolve()).replace('\\','/')
    return '/'+value[0].lower()+value[2:] if len(value)>2 and value[1]==':' else value

def check(value,label):
    checks.append((label,bool(value)))
    if not value:
        raise AssertionError(label)

entries={
 'inventory':pathlib.Path('Printing/get-printer-inventory.sh'),
 'export':pathlib.Path('Printing/export-print-configuration.sh'),
 'remote':pathlib.Path('Network-and-DNS/test-remote-access.sh'),
 'access':pathlib.Path('Users-and-Groups/audit-ssh-access.sh'),
}

for relative in [*entries.values(),pathlib.Path('lib/common.inc'),pathlib.Path('lib/cups-audit.inc'),pathlib.Path('lib/ssh-audit.inc')]:
    result=subprocess.run([args.shell,'-n',shell_path(ROOT/relative)],capture_output=True,text=True)
    check(result.returncode==0,str(relative)+' syntax')

logging='''printf '%s' "$0" >> "$FIXTURE_LOG"
for value do printf '\\t%s' "$value" >> "$FIXTURE_LOG"; done
printf '\\n' >> "$FIXTURE_LOG"
'''
providers={
 'uname':'''case "$1" in -s) echo Linux;; -m) echo x86_64;; *) echo fixture;; esac
''',
 'lpstat':logging+'''case "$1" in
 -r) echo 'scheduler is running';;
 -d) echo 'system default destination: fixture';;
 -p) echo "printer ${2:-fixture} is idle";;
 -a) echo "${2:-fixture} accepting requests";;
 -v) echo 'device for fixture: smb://domain/user:URI_SECRET@server/share?token=QUERY_SECRET'; [ "$MOCK_LPSTAT_FAIL" != yes ] || exit 7;;
esac
''',
 'lpinfo':logging+'''echo 'fixture-driver Fixture approved driver'
''',
 'sshd':logging+'''case "$1" in
 -t) [ "$MOCK_SSH_SYNTAX_FAIL" != yes ] || exit 9;;
 -T)
  if [ "$MOCK_SSH_POLICY_FAIL" = yes ]; then echo RAW_FAILURE_SECRET; exit 7; fi
  printf '%s\\n' 'port 22' 'listenaddress 0.0.0.0:22' 'permitrootlogin no' 'passwordauthentication no' 'pubkeyauthentication yes' 'authenticationmethods publickey' 'maxauthtries 3' 'usepam yes' 'allowtcpforwarding no' 'kbdinteractiveauthentication no' 'allowusers fixture' 'allowgroups technicians' 'denyusers guest' 'denygroups guests' 'authorizedkeysfile .ssh/authorized_keys' 'strictmodes yes' 'setenv UNSAFE_SECRET=not-exported';;
esac
''',
 'ssh-keygen':logging+'''echo '256 SHA256:fixture PUBLIC_COMMENT_SECRET (ED25519)'
''',
 'ss':logging+'''echo 'State Recv-Q Send-Q Local Address:Port Peer Address:Port'
echo 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*'
''',
 'ip':logging+'''echo 'default via 192.0.2.1 dev eth0'
''',
 'python3':logging+'''echo 'TCP connection established; authentication not attempted'
''',
}

def scenario(name,values=(),*,missing=(),extra_env=None):
    folder=BASE/('case-'+str(len(checks)))
    library=folder/'Linux'
    mock=folder/'mock'
    mock.mkdir(parents=True)
    fs=folder/'fs'
    cups=fs/'etc/cups'
    (cups/'ppd').mkdir(parents=True)
    home=fs/'home/fixture'
    (home/'.ssh').mkdir(parents=True)
    (home/'.ssh/authorized_keys').write_text('fixture-public-key-only\n',encoding='utf-8')
    (fs/'etc/passwd').write_text('fixture:x:1000:1000:Fixture:'+shell_path(home)+':/bin/sh\n',encoding='utf-8')
    (cups/'printers.conf').write_text('<Printer fixture>\nShared Yes\nState Idle\nAccepting Yes\nErrorPolicy retry-job\nOpPolicy default\nDeviceURI ipp://name:CONFIG_SECRET@host/\nAuthInfoRequired CONFIG_SECRET\n</Printer>\n',encoding='utf-8')
    (cups/'cupsd.conf').write_text('Listen localhost:631\nPort 631\nBrowsing Yes\nWebInterface No\nDefaultAuthType Basic\nDefaultEncryption Required\nServerKey CONFIG_SECRET\n',encoding='utf-8')
    (cups/'ppd/fixture.ppd').write_text('PPD_BODY_SECRET\n',encoding='utf-8')
    for relative in [*entries.values(),pathlib.Path('lib/common.inc'),pathlib.Path('lib/cups-audit.inc'),pathlib.Path('lib/ssh-audit.inc')]:
        dest=library/relative
        dest.parent.mkdir(parents=True,exist_ok=True)
        text=(ROOT/relative).read_text(encoding='utf-8')
        # Test-only copies redirect selected native paths. Production library has no test override.
        if relative.name=='cups-audit.inc': text=text.replace('/etc/cups',shell_path(cups))
        if relative.name=='ssh-audit.inc':
            text=text.replace('/etc/passwd',shell_path(fs/'etc/passwd')).replace('/usr/sbin/sshd',shell_path(fs/'missing-sshd'))
        if relative.name=='common.inc':
            text+='''
# Fixture-only capability boundary: no real optional provider can be reached.
have() {
 case "$1" in
  lpstat|lpinfo|sshd|ssh-keygen|ss|ip|python3) [ -x "$FIXTURE_BIN/$1" ];;
  ls) command -v ls >/dev/null 2>&1;;
  "$FIXTURE_BIN"/*) [ -x "$1" ];;
  *) [ "$(command -v "$1")" = "$1" ];;
 esac
}
'''
        dest.write_text(text,encoding='utf-8',newline='\n')
    for command,body in providers.items():
        if command in missing: continue
        path=mock/command
        path.write_text('#!/bin/sh\n'+body,encoding='utf-8',newline='\n')
        path.chmod(0o755)
    report_base=folder/'reports'
    runner=folder/'run.sh'
    env=''
    for key,value in (extra_env or {}).items(): env+=key+'='+shlex.quote(value)+'; export '+key+'\n'
    command=' '.join(shlex.quote(str(v)) for v in values)
    runner.write_text(
        'PATH='+shlex.quote(shell_path(mock))+':/usr/bin:/bin; export PATH\n'
        'FIXTURE_BIN='+shlex.quote(shell_path(mock))+'; export FIXTURE_BIN\n'
        'FIXTURE_LOG='+shlex.quote(shell_path(folder/'commands.log'))+'; export FIXTURE_LOG\n'
        +env+'exec '+shlex.quote(shell_path(library/entries[name]))+' --output-dir '+shlex.quote(shell_path(report_base))+' '+command+'\n',
        encoding='utf-8',newline='\n')
    # Explicit shell invocation does not depend on executable mode retained by Windows file copies.
    source=runner.read_text(encoding='utf-8').replace('exec '+shlex.quote(shell_path(library/entries[name])),'exec sh '+shlex.quote(shell_path(library/entries[name])))
    runner.write_text(source,encoding='utf-8',newline='\n')
    result=subprocess.run([args.shell,shell_path(runner)],capture_output=True,text=True,timeout=20)
    reports=list(report_base.glob('*')) if report_base.exists() else []
    report=reports[0] if reports else None
    output={p.name:p.read_text(encoding='utf-8') for p in report.iterdir() if p.is_file()} if report else {}
    log=(folder/'commands.log').read_text(encoding='utf-8') if (folder/'commands.log').exists() else ''
    (folder/'execution.json').write_text(json.dumps({'code':result.returncode,'out':result.stdout,'err':result.stderr},indent=2),encoding='utf-8')
    return result,output,log,report

result,output,log,report=scenario('inventory',('--queue','fixture'))
check(result.returncode==0,'Inventory full wrapper finishes successfully with complete mocks')
for label in ('cups-scheduler','default-printer','queues','accepting','device-endpoints','installed-drivers','sharing'):
    check(label+'.txt' in output,'Inventory retains '+label+' filename')
check('\t-p\tfixture' in log and '\t-a\tfixture' in log and '\t-v\tfixture' in log,'Inventory queue selector reaches all scoped lpstat calls')
check('fixture-driver' in output['installed-drivers.txt'],'Installed driver listing retained')
check('Shared Yes' in output['sharing.txt'] and 'ErrorPolicy' not in output['sharing.txt'],'Inventory sharing view remains narrow')
check('URI_SECRET' not in '\n'.join(output.values()) and 'CONFIG_SECRET' not in '\n'.join(output.values()),'Inventory excludes URI/config credentials')
check('State Idle' not in output['sharing.txt'],'Export-only metadata is not silently added to inventory')

result,output,log,report=scenario('export')
check(result.returncode==0,'Export full wrapper finishes successfully')
for label in ('default-printer','queue-state','queue-accepting','sanitized-devices','queue-metadata','scheduler-metadata','ppd-file-names'):
    check(label+'.txt' in output,'Export retains '+label+' filename')
check('ErrorPolicy retry-job' in output['queue-metadata.txt'] and 'OpPolicy default' in output['queue-metadata.txt'],'Export retains extended printer metadata')
check('DefaultEncryption Required' in output['scheduler-metadata.txt'],'Export retains whitelisted scheduler security settings')
check('fixture.ppd' in output['ppd-file-names.txt'] and 'PPD_BODY_SECRET' not in '\n'.join(output.values()),'PPD names are exported without contents')
check('SECRET' not in '\n'.join(output.values()),'Export excludes URI/query/config secrets')
check('installed-drivers.txt' not in output and '\t-m' not in log,'Export does not silently add global driver inventory')
check('cannot restore a complete CUPS server' in output['findings.tsv'],'Export preserves non-backup interpretation')

result,output,log,report=scenario('inventory',('--queue','bad/queue'))
check(result.returncode==2 and '\t-p' not in log,'Invalid inventory queue rejected before CUPS collection')
result,output,log,report=scenario('export',missing=('lpstat','lpinfo'))
check(result.returncode==3 and 'Unknown\tcups' in output['findings.tsv'],'Missing CUPS provider remains Unknown')
result,output,log,report=scenario('export',extra_env={'MOCK_LPSTAT_FAIL':'yes'})
check(result.returncode==3 and 'exit 7' in output['findings.tsv'],'Shared CUPS endpoint collector preserves provider failure')
check('URI_SECRET' not in '\n'.join(output.values()),'Failed CUPS probe never leaks partial credentials')

result,output,log,report=scenario('remote')
check(result.returncode==0,'Remote-access full wrapper succeeds')
check('sshd-effective.txt' in output and 'listening-sockets.txt' in output and 'routes.txt' in output,'Remote-access legacy evidence names retained')
check('\t-T\t-C\tuser=root,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22' in log,'Remote default Match context preserved exactly')
check('allowtcpforwarding no' in output['sshd-effective.txt'],'Remote-specific forwarding policy retained')
check('allowusers' not in output['sshd-effective.txt'],'Remote policy projection remains narrow')
check('ssh-tcp.txt' not in output,'External TCP request remains opt-in')

result,output,log,report=scenario('remote',('--target','server.example','--port','2222','--user','fixture','--client-address','192.0.2.10','--local-address','192.0.2.20'))
check(result.returncode==0 and 'ssh-tcp.txt' in output,'Selected TCP test remains available')
check('user=fixture,host=localhost,addr=192.0.2.10,laddr=192.0.2.20,lport=2222' in log,'Remote selected local/client/port context retained')
check('\tserver.example\t2222' in log,'TCP destination and port reach bounded mock provider')

result,output,log,report=scenario('access')
check(result.returncode==0,'SSH access full wrapper succeeds with default policy')
check('default-ssh-policy.txt' in output and 'effective-ssh-policy.txt' not in output,'Default access-policy filename retained')
check('\t-T\t-C' not in log,'Access audit does not invent a Match context')
check('allowusers fixture' in output['default-ssh-policy.txt'] and 'authorizedkeysfile' in output['default-ssh-policy.txt'],'Access policy projection retains authorization fields')
check('allowtcpforwarding' not in output['default-ssh-policy.txt'],'Access policy projection does not silently become remote projection')
check('UNSAFE_SECRET' not in '\n'.join(output.values()),'Unselected effective policy values stay excluded')

result,output,log,report=scenario('access',('--user','fixture','--client-address','192.0.2.10','--client-host','client.example'))
check(result.returncode==0,'Selected access policy and public-key audit succeed')
check('effective-ssh-policy.txt' in output,'Selected Match policy retains evidence filename')
check('\t-T\t-C\tuser=fixture,host=client.example,addr=192.0.2.10' in log,'Access selected Match context preserves host meaning')
check('ssh-file-metadata.txt' in output and 'public-key-fingerprints.txt' in output,'Selected file metadata and fingerprints retained')
check('SHA256:fixture' in output['public-key-fingerprints.txt'] and 'PUBLIC_COMMENT_SECRET' not in '\n'.join(output.values()),'Key fingerprints exclude key comments')
check(not any('private' in name for name in output),'Shared policy/key collector leaves no raw temporary spool')

result,output,log,report=scenario('access',('--user','fixture'))
check(result.returncode==0 and 'default-ssh-policy.txt' in output and '\t-T\t-C' not in log,'Incomplete Match inputs retain default policy and selected-user key audit')
result,output,log,report=scenario('remote',extra_env={'MOCK_SSH_POLICY_FAIL':'yes'})
check(result.returncode==3 and 'Unknown\tsshd-effective' in output['findings.tsv'] and 'exit 7' in output['findings.tsv'],'Remote shared policy failure remains Unknown')
check('RAW_FAILURE_SECRET' not in '\n'.join(output.values()),'Failed policy output is discarded before persistence')
result,output,log,report=scenario('access',extra_env={'MOCK_SSH_SYNTAX_FAIL':'yes'})
check(result.returncode==3 and 'Unknown\tssh-config-test' in output['findings.tsv'],'Access syntax failure preserves exit/evidence handling')
result,output,log,report=scenario('remote',missing=('sshd',))
check(result.returncode==3 and 'Unknown\tsshd' in output['findings.tsv'],'Missing SSH server remains Unknown')
result,output,log,report=scenario('remote',('--port','70000'))
check(result.returncode==2 and '\t-T' not in log,'Invalid SSH port rejected before policy evaluation')

summary={'checks':len(checks),'failed':sum(not value for _,value in checks),'evidence':str(BASE),'scope':'Four actual compatibility entrypoints, private copies of real shared libraries, private configuration/public-key fixtures, mocked providers; no live CUPS/SSH/socket activity.'}
(BASE/'test-results.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print(json.dumps(summary,indent=2))
